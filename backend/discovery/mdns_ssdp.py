import socket
import select
import time
import re
import urllib.request
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
SSDP_MX = 2

def discover_ssdp(timeout: float = 2.5) -> List[Dict[str, Any]]:
    """Discovers UPnP / SSDP devices on the local subnet by broadcasting M-SEARCH."""
    results = []
    seen_ips = set()

    message = (
        f"M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
        f'MAN: "ssdp:discover"\r\n'
        f"MX: {SSDP_MX}\r\n"
        f"ST: ssdp:all\r\n\r\n"
    ).encode("utf-8")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)

        # Broadcast M-SEARCH
        sock.sendto(message, (SSDP_ADDR, SSDP_PORT))

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                data, (ip, port) = sock.recvfrom(4096)
                resp_text = data.decode("utf-8", errors="ignore")
                headers = {}
                for line in resp_text.split("\r\n"):
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip().upper()] = v.strip()

                if ip not in seen_ips:
                    seen_ips.add(ip)
                    location = headers.get("LOCATION", "")
                    server = headers.get("SERVER", "")
                    st = headers.get("ST", "")

                    device_info = {
                        "ip": ip,
                        "protocol": "SSDP/UPnP",
                        "server": server,
                        "location": location,
                        "service_type": st,
                        "friendly_name": None,
                        "manufacturer": None,
                        "model": None,
                    }

                    # If location URL is present, attempt fast parse of XML device description
                    if location and location.startswith("http"):
                        xml_meta = _fetch_upnp_xml(location)
                        if xml_meta:
                            device_info.update(xml_meta)

                    results.append(device_info)
            except socket.timeout:
                break
            except Exception:
                continue
        sock.close()
    except Exception as e:
        # Socket or permission limitation
        pass

    return results

def _fetch_upnp_xml(url: str, timeout: float = 1.0) -> Optional[Dict[str, str]]:
    """Fetches UPnP XML descriptor and extracts friendlyName, model, manufacturer."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "IoT-Risk-Assessment-Engine/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read()
            # Strip XML namespaces for simple XPath / tag search
            xml_str = re.sub(r'xmlns(:\w+)?="[^"]+"', '', content.decode("utf-8", errors="ignore"))
            root = ET.fromstring(xml_str)
            
            def find_text(tag: str) -> Optional[str]:
                el = root.find(f".//{tag}")
                return el.text.strip() if el is not None and el.text else None

            friendly_name = find_text("friendlyName")
            manufacturer = find_text("manufacturer")
            model_name = find_text("modelName")
            model_number = find_text("modelNumber")

            return {
                "friendly_name": friendly_name,
                "manufacturer": manufacturer,
                "model": f"{model_name or ''} {model_number or ''}".strip() or None,
            }
    except Exception:
        return None

def discover_mdns(timeout: float = 2.0) -> List[Dict[str, Any]]:
    """Probes mDNS multicast for smart home services (Google Cast, AirPlay, HomeKit, Sonos)."""
    results = []
    seen_ips = set()
    MDNS_ADDR = "224.0.0.251"
    MDNS_PORT = 5353

    # Standard DNS query for _services._dns-sd._udp.local (PTR query)
    # Header: ID=0, Flags=0, Questions=1, Answer=0, Auth=0, Add=0
    query = (
        b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x09_services\x07_dns-sd\x04_udp\x05local\x00"
        b"\x00\x0c\x00\x01" # Type PTR, Class IN
    )

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)

        sock.sendto(query, (MDNS_ADDR, MDNS_PORT))

        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                data, (ip, port) = sock.recvfrom(4096)
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    results.append({
                        "ip": ip,
                        "protocol": "mDNS",
                        "raw_bytes_len": len(data)
                    })
            except socket.timeout:
                break
            except Exception:
                continue
        sock.close()
    except Exception:
        pass

    return results
