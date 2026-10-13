import asyncio
import socket
import ipaddress
import subprocess
import re
import os
import psutil
from typing import List, Dict, Any, Optional, Set, Callable
from scapy.all import Ether, ARP, srp, conf
from backend.discovery.fingerprint import lookup_vendor_by_mac, resolve_hostname, classify_device
from backend.discovery.mdns_ssdp import discover_ssdp, discover_mdns
from backend.database import get_db_connection

conf.verb = 0

def get_network_interfaces() -> List[Dict[str, Any]]:
    """Detects all valid IPv4 network interfaces on the host."""
    interfaces = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for name, addr_list in addrs.items():
        is_up = stats[name].isup if name in stats else True
        for addr in addr_list:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                ip = addr.address
                netmask = addr.netmask or "255.255.255.0"
                try:
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    cidr = str(network)
                    interfaces.append({
                        "name": name,
                        "ip": ip,
                        "netmask": netmask,
                        "cidr": cidr,
                        "is_up": is_up,
                        "broadcast": str(network.broadcast_address) if network.num_addresses > 1 else None,
                        "host_count": min(network.num_addresses - 2, 254) if network.num_addresses > 2 else 1
                    })
                except Exception:
                    pass
    return interfaces

def normalize_mac(mac_str: str) -> str:
    cleaned = mac_str.replace("-", ":")
    parts = cleaned.split(":")
    if len(parts) == 6:
        return ":".join(p.zfill(2).upper() for p in parts)
    return cleaned.upper()

def get_system_arp_cache() -> Dict[str, str]:
    """Extracts IP -> MAC mapping from the host operating system ARP table (Windows, Linux, macOS, Docker)."""
    arp_map = {}

    # 1. Linux /proc/net/arp
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp", "r") as f:
                lines = f.readlines()[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        mac = normalize_mac(parts[3])
                        if mac != "00:00:00:00:00:00" and not ip.startswith("224."):
                            arp_map[ip] = mac
        except Exception:
            pass

    # 2. Modern Linux 'ip neigh'
    if not arp_map and os.name != 'nt':
        try:
            output = subprocess.check_output("ip neigh", shell=True, text=True, stderr=subprocess.DEVNULL)
            for line in output.splitlines():
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]{11,17})", line)
                if match:
                    ip = match.group(1)
                    mac = normalize_mac(match.group(2))
                    arp_map[ip] = mac
        except Exception:
            pass

    # 3. Universal 'arp -a' (Windows, macOS, Linux)
    try:
        output = subprocess.check_output("arp -a", shell=True, text=True, stderr=subprocess.DEVNULL)
        for line in output.splitlines():
            line = line.strip()
            match = re.search(r"\(?(\d+\.\d+\.\d+\.\d+)\)?\s+(?:at\s+)?([0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2}[:-][0-9a-fA-F]{1,2})", line)
            if match:
                ip = match.group(1)
                mac = normalize_mac(match.group(2))
                if not (ip.startswith("224.") or ip.startswith("239.") or ip.endswith(".255") or ip == "255.255.255.255"):
                    arp_map[ip] = mac
    except Exception:
        pass
    return arp_map

get_windows_arp_cache = get_system_arp_cache

def scapy_arp_scan(cidr: str, timeout: float = 1.0) -> Dict[str, str]:
    """Layer 2 ARP sweep using Scapy."""
    results = {}
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=cidr), timeout=timeout, verbose=0, retry=1)
        for _, rcv in ans:
            ip = rcv.psrc
            mac = rcv.hwsrc.upper()
            results[ip] = mac
    except Exception:
        pass
    return results

async def check_host_tcp_alive(ip: str, ports: List[int] = [80, 443, 22, 554, 8080, 23, 1883, 53], timeout: float = 0.25) -> Optional[int]:
    """Pure async non-blocking TCP Connect sweep across common IoT ports."""
    for port in ports:
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return port
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            continue
    return None

class NetworkDiscoveryEngine:
    def __init__(self):
        self.is_scanning = False
        self.progress = 0
        self.found_devices: List[Dict[str, Any]] = []

    async def run_discovery(
        self,
        target_cidr: Optional[str] = None,
        scan_type: str = "FULL",
        progress_callback: Optional[Callable[[Dict[str, Any]], Any]] = None
    ) -> List[Dict[str, Any]]:
        self.is_scanning = True
        self.progress = 5
        self.found_devices = []

        async def notify(msg: Dict[str, Any]):
            if progress_callback:
                if asyncio.iscoroutinefunction(progress_callback):
                    await progress_callback(msg)
                else:
                    progress_callback(msg)

        try:
            # 1. Targets
            targets = []
            if target_cidr and target_cidr.strip():
                for c in target_cidr.split(","):
                    c_clean = c.strip()
                    if c_clean:
                        targets.append(c_clean)
            else:
                for iface in get_network_interfaces():
                    if iface["is_up"] and not iface["ip"].startswith("169.254"):
                        targets.append(iface["cidr"])

            if not targets:
                targets = ["192.168.137.0/24"]

            await notify({"status": "RUNNING", "progress": 10, "message": f"Scanning targets: {', '.join(targets)}"})

            # 2. Layer 2 ARP Cache
            arp_table = await asyncio.to_thread(get_windows_arp_cache)

            # Scapy ARP in worker thread
            if scan_type in ["FULL", "ARP"]:
                for t in targets:
                    try:
                        scapy_res = await asyncio.to_thread(scapy_arp_scan, t, 1.0)
                        arp_table.update(scapy_res)
                    except Exception:
                        pass

            self.progress = 30
            await notify({
                "status": "RUNNING",
                "progress": 30,
                "message": f"Layer 2 ARP discovered {len(arp_table)} active hosts",
                "found_count": len(arp_table)
            })

            # 3. Layer 3 Multi-Subnet TCP Sweep
            discovered_alive_ips: Set[str] = set(arp_table.keys())

            if scan_type in ["FULL", "TCP_SWEEP"]:
                candidate_ips = []
                for target in targets:
                    try:
                        net = ipaddress.IPv4Network(target, strict=False)
                        hosts = list(net.hosts())[:254]
                        candidate_ips.extend([str(h) for h in hosts])
                    except Exception:
                        pass

                # Semaphore-controlled concurrent TCP sweep (up to 50 concurrent sockets)
                sem = asyncio.Semaphore(50)

                async def sweep_worker(ip_addr: str):
                    async with sem:
                        p = await check_host_tcp_alive(ip_addr, timeout=0.25)
                        if p is not None:
                            discovered_alive_ips.add(ip_addr)

                total_cand = len(candidate_ips)
                if total_cand > 0:
                    chunk_size = 50
                    for i in range(0, total_cand, chunk_size):
                        chunk = candidate_ips[i:i + chunk_size]
                        await asyncio.gather(*(sweep_worker(ip) for ip in chunk))
                        self.progress = min(70, 30 + int(40 * ((i + len(chunk)) / total_cand)))
                        await notify({
                            "status": "RUNNING",
                            "progress": self.progress,
                            "message": f"TCP sweeping subnets ({i + len(chunk)}/{total_cand} IPs checked)",
                            "found_count": len(discovered_alive_ips)
                        })

            # 4. Multicast SSDP & mDNS discovery in background thread
            if scan_type in ["FULL"]:
                ssdp_devices = await asyncio.to_thread(discover_ssdp, 1.5)
                ssdp_by_ip = {d["ip"]: d for d in ssdp_devices}
                for ip in ssdp_by_ip.keys():
                    discovered_alive_ips.add(ip)
            else:
                ssdp_by_ip = {}

            self.progress = 80
            await notify({
                "status": "RUNNING",
                "progress": 80,
                "message": f"Fingerprinting and classifying {len(discovered_alive_ips)} live hosts...",
                "found_count": len(discovered_alive_ips)
            })

            # 5. Enrich and Store
            conn = get_db_connection()
            cursor = conn.cursor()
            saved_devices = []

            for ip in sorted(discovered_alive_ips):
                mac = arp_table.get(ip)
                vendor = lookup_vendor_by_mac(mac)
                hostname = await asyncio.to_thread(resolve_hostname, ip)

                ssdp_info = ssdp_by_ip.get(ip, {})
                model = ssdp_info.get("model")
                manufacturer = ssdp_info.get("manufacturer")
                friendly_name = ssdp_info.get("friendly_name")

                if manufacturer and vendor in ["Unknown", "Unknown Device Vendor"]:
                    vendor = manufacturer
                if friendly_name and not hostname:
                    hostname = friendly_name

                device_type = classify_device(vendor, hostname, [], [ssdp_info.get("server", "")])

                cursor.execute("""
                    INSERT INTO devices (ip, mac, hostname, vendor, device_type, model, status, last_seen, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, 'Active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    ON CONFLICT(ip) DO UPDATE SET
                        mac=COALESCE(excluded.mac, devices.mac),
                        hostname=COALESCE(excluded.hostname, devices.hostname),
                        vendor=CASE WHEN excluded.vendor != 'Unknown' THEN excluded.vendor ELSE devices.vendor END,
                        device_type=CASE WHEN devices.device_type = 'Generic IoT' THEN excluded.device_type ELSE devices.device_type END,
                        model=COALESCE(excluded.model, devices.model),
                        status='Active',
                        last_seen=CURRENT_TIMESTAMP,
                        updated_at=CURRENT_TIMESTAMP
                """, (ip, mac, hostname, vendor, device_type, model))

                cursor.execute("SELECT id FROM devices WHERE ip = ?", (ip,))
                row = cursor.fetchone()
                dev_id = row["id"] if row else None

                cursor.execute("""
                    INSERT INTO exposure_metrics (device_id, reachability, subnet, updated_at)
                    VALUES (?, 'Local Subnet', ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(device_id) DO UPDATE SET updated_at=CURRENT_TIMESTAMP
                """, (dev_id, f"{ip.rsplit('.', 1)[0]}.0/24"))

                saved_devices.append({
                    "id": dev_id,
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "vendor": vendor,
                    "device_type": device_type,
                    "model": model,
                    "status": "Active"
                })

            conn.commit()
            conn.close()

            self.found_devices = saved_devices
            self.progress = 100

            await notify({
                "status": "COMPLETED",
                "progress": 100,
                "message": f"Discovery complete! Found and registered {len(saved_devices)} assets.",
                "devices": saved_devices
            })

            return saved_devices
        finally:
            self.is_scanning = False
