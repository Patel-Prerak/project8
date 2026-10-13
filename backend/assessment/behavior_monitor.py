import threading
import time
import socket
from collections import defaultdict
from typing import Dict, Any, List, Optional, Set
from scapy.all import sniff, IP, TCP, UDP, DNS, conf
from backend.database import get_db_connection

conf.verb = 0

class IoTBehaviorMonitor:
    def __init__(self):
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        
        # Per-IP metrics
        # ip -> { "pkts_in": int, "pkts_out": int, "bytes_in": int, "bytes_out": int, "dest_ports": set(), "dest_ips": set(), "last_seen": float }
        self.stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "pkts_in": 0,
            "pkts_out": 0,
            "bytes_in": 0,
            "bytes_out": 0,
            "dest_ports": set(),
            "dest_ips": set(),
            "recent_packets": [],
            "last_seen": time.time()
        })
        self.recent_events: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

    def start(self):
        if self.is_running:
            return
        self.is_running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.is_running = False

    def _packet_handler(self, pkt):
        if not self.is_running:
            return
        
        now = time.time()
        pkt_len = len(pkt)

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # Update outbound for src_ip
            with self._lock:
                s_stat = self.stats[src_ip]
                s_stat["pkts_out"] += 1
                s_stat["bytes_out"] += pkt_len
                s_stat["last_seen"] = now
                s_stat["dest_ips"].add(dst_ip)
                s_stat["recent_packets"].append(now)

                # Keep only last 10 seconds of timestamps
                s_stat["recent_packets"] = [t for t in s_stat["recent_packets"] if now - t < 10.0]

                # Update inbound for dst_ip
                d_stat = self.stats[dst_ip]
                d_stat["pkts_in"] += 1
                d_stat["bytes_in"] += pkt_len
                d_stat["last_seen"] = now

                dport = None
                if TCP in pkt:
                    dport = pkt[TCP].dport
                    s_stat["dest_ports"].add(dport)
                elif UDP in pkt:
                    dport = pkt[UDP].dport
                    s_stat["dest_ports"].add(dport)

            # Anomaly Detection Checks
            self._evaluate_anomalies(src_ip, dst_ip, dport, s_stat, now)

    def _evaluate_anomalies(self, src_ip: str, dst_ip: str, dport: Optional[int], stat: Dict[str, Any], now: float):
        # 1. Port Scanning Behavior (contacting > 12 distinct ports)
        if len(stat["dest_ports"]) >= 12:
            self._log_anomaly(
                device_ip=src_ip,
                event_type="PORT_SCAN_DETECTED",
                severity="High",
                title="Suspicious Network Reconnaissance / Port Scan",
                details=f"Device contacted {len(stat['dest_ports'])} distinct ports across the network, characteristic of automated worm/botnet propagation."
            )
            # Reset port set to prevent event spam
            stat["dest_ports"].clear()

        # 2. High-Frequency Traffic Flood / Spike (> 120 packets in 10s from single device)
        if len(stat["recent_packets"]) > 120:
            self._log_anomaly(
                device_ip=src_ip,
                event_type="TRAFFIC_SPIKE_DETECTED",
                severity="High",
                title="Abnormal Traffic Spike / High Packet Volume",
                details=f"Device generated {len(stat['recent_packets'])} packets in 10 seconds. Potential DDoS involvement or data exfiltration."
            )
            stat["recent_packets"].clear()

        # 3. Suspicious Outbound Port (C2 / Reverse Shell ports)
        SUSPICIOUS_C2_PORTS = {4444, 5555, 6667, 1337, 31337, 8888, 9999}
        if dport in SUSPICIOUS_C2_PORTS and not dst_ip.startswith("127."):
            self._log_anomaly(
                device_ip=src_ip,
                event_type="SUSPICIOUS_C2_COMMUNICATION",
                severity="Critical",
                title="Suspicious Outbound Port Communication (Potential C2)",
                details=f"Device initiated outbound connection to {dst_ip} on known suspicious port {dport}."
            )

    def _log_anomaly(self, device_ip: str, event_type: str, severity: str, title: str, details: str):
        # Throttle similar events in short timeframe
        for ev in self.recent_events[-10:]:
            if ev["device_ip"] == device_ip and ev["event_type"] == event_type and time.time() - ev.get("_ts", 0) < 30:
                return

        event = {
            "device_ip": device_ip,
            "event_type": event_type,
            "severity": severity,
            "title": title,
            "details": details,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "_ts": time.time()
        }
        self.recent_events.append(event)
        if len(self.recent_events) > 50:
            self.recent_events.pop(0)

        # Persist to database
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM devices WHERE ip = ?", (device_ip,))
            row = cursor.fetchone()
            device_id = row["id"] if row else None

            cursor.execute("""
                INSERT INTO behavior_events (device_id, device_ip, event_type, severity, title, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (device_id, device_ip, event_type, severity, title, details))
            conn.commit()
            conn.close()
        except Exception:
            pass

    def _sniff_loop(self):
        try:
            # Sniff with stop_filter so it exits cleanly when is_running is False
            sniff(prn=self._packet_handler, store=0, stop_filter=lambda p: not self.is_running)
        except Exception:
            # If WinPcap/Npcap has permissions or is unavailable, fallback to socket listener or periodic netstat
            self._socket_fallback_loop()

    def _socket_fallback_loop(self):
        """Fallback connection and netflow tracker if raw socket packet capture is restricted."""
        while self.is_running:
            time.sleep(2.0)
            try:
                # Query active network connections via psutil
                import psutil
                conns = psutil.net_connections(kind="inet")
                now = time.time()
                for c in conns:
                    if c.raddr:
                        r_ip, r_port = c.raddr.ip, c.raddr.port
                        with self._lock:
                            s = self.stats[r_ip]
                            s["pkts_in"] += 1
                            s["bytes_in"] += 64
                            s["last_seen"] = now
            except Exception:
                pass

    def get_device_traffic(self, ip: str) -> Dict[str, Any]:
        with self._lock:
            s = self.stats.get(ip, {
                "pkts_in": 0, "pkts_out": 0, "bytes_in": 0, "bytes_out": 0, "dest_ports": set(), "dest_ips": set()
            })
            return {
                "ip": ip,
                "packets_in": s["pkts_in"],
                "packets_out": s["pkts_out"],
                "bytes_in": s["bytes_in"],
                "bytes_out": s["bytes_out"],
                "active_destinations_count": len(s["dest_ips"]),
                "contacted_ports_count": len(s["dest_ports"]),
                "bandwidth_kb": round((s["bytes_in"] + s["bytes_out"]) / 1024, 2)
            }

    def get_all_anomalies(self) -> List[Dict[str, Any]]:
        return list(self.recent_events)

# Global monitor instance
behavior_monitor = IoTBehaviorMonitor()
