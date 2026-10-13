import asyncio
import socket
from typing import List, Dict, Any, Tuple, Optional

# Comprehensive IoT & Infrastructure Port Registry
IOT_PORT_REGISTRY = {
    21: {"name": "FTP", "insecure": True, "desc": "File Transfer Protocol (Cleartext)"},
    22: {"name": "SSH", "insecure": False, "desc": "Secure Shell Management"},
    23: {"name": "Telnet", "insecure": True, "desc": "Telnet Remote Shell (Insecure/Cleartext)"},
    25: {"name": "SMTP", "insecure": True, "desc": "Simple Mail Transfer"},
    53: {"name": "DNS", "insecure": False, "desc": "Domain Name System"},
    80: {"name": "HTTP", "insecure": True, "desc": "Web Interface (Cleartext)"},
    110: {"name": "POP3", "insecure": True, "desc": "POP3 Email (Cleartext)"},
    143: {"name": "IMAP", "insecure": True, "desc": "IMAP Email (Cleartext)"},
    443: {"name": "HTTPS", "insecure": False, "desc": "Encrypted Web Management"},
    554: {"name": "RTSP", "insecure": True, "desc": "Real Time Streaming Protocol (Surveillance Video)"},
    1883: {"name": "MQTT", "insecure": True, "desc": "MQTT IoT Broker (Cleartext / Unencrypted)"},
    1900: {"name": "SSDP/UPnP", "insecure": True, "desc": "Universal Plug and Play Discovery"},
    5000: {"name": "UPnP/Web", "insecure": True, "desc": "UPnP Control / Alternative Web UI"},
    5060: {"name": "SIP", "insecure": True, "desc": "Session Initiation Protocol (VoIP/Doorbell)"},
    5353: {"name": "mDNS", "insecure": False, "desc": "Multicast DNS"},
    5683: {"name": "CoAP", "insecure": True, "desc": "Constrained Application Protocol (Cleartext UDP)"},
    8008: {"name": "Google Cast", "insecure": True, "desc": "Chromecast / Google Assistant API"},
    8080: {"name": "HTTP-Alt", "insecure": True, "desc": "Alternative Web Management"},
    8443: {"name": "HTTPS-Alt", "insecure": False, "desc": "Alternative SSL/TLS Management"},
    8554: {"name": "RTSP-Alt", "insecure": True, "desc": "Secondary RTSP Video Streaming"},
    8883: {"name": "MQTTS", "insecure": False, "desc": "Secure MQTT with TLS"},
    9000: {"name": "Camera-UI", "insecure": True, "desc": "CCTV / IP Camera Management Port"},
    49152: {"name": "UPnP-Event", "insecure": True, "desc": "UPnP Eventing / Subscriptions"},
}

async def scan_port(ip: str, port: int, timeout: float = 0.5) -> Optional[Dict[str, Any]]:
    """Checks if a TCP port is open."""
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        
        meta = IOT_PORT_REGISTRY.get(port, {"name": f"TCP/{port}", "insecure": False, "desc": "Custom Port"})
        return {
            "port": port,
            "protocol": "TCP",
            "service_name": meta["name"],
            "is_insecure": meta["insecure"],
            "desc": meta["desc"],
        }
    except Exception:
        return None

async def scan_device_ports(ip: str, ports: Optional[List[int]] = None, timeout: float = 0.45) -> List[Dict[str, Any]]:
    """Scans all registered IoT and standard ports concurrently."""
    if ports is None:
        ports = list(IOT_PORT_REGISTRY.keys())
    
    tasks = [scan_port(ip, p, timeout) for p in ports]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]
