import ipaddress
from typing import Dict, Any, List, Optional

def analyze_network_exposure(
    ip: str,
    open_ports: List[int],
    insecure_services_count: int,
    gateway_ip: Optional[str] = "192.168.137.1"
) -> Dict[str, Any]:
    """Evaluates network reachability, segmentation, and attack surface score."""
    ports_set = set(open_ports)
    total_ports = len(open_ports)

    # 1. IP routability & network classification
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        is_private = ip_obj.is_private
        is_loopback = ip_obj.is_loopback
        subnet = f"{ip.rsplit('.', 1)[0]}.0/24"
    except Exception:
        is_private = True
        is_loopback = False
        subnet = "192.168.137.0/24"

    # Check gateway adjacency
    is_gateway_adjacent = False
    if gateway_ip and gateway_ip.rsplit(".", 1)[0] == ip.rsplit(".", 1)[0]:
        is_gateway_adjacent = True

    # VLAN Assessment
    # If device is on same subnet as default gateway and not segmented
    vlan_status = "Default Management Subnet (VLAN 1)" if is_gateway_adjacent else "Segmented Subnet"
    isolation_recommended = True if is_gateway_adjacent and insecure_services_count > 0 else False

    # 2. Attack Surface Score (0.0 - 10.0)
    # Baseline for having any open port: 2.0
    # +1.2 per insecure service (Telnet, FTP, plain HTTP, RTSP)
    # +0.4 per standard open port
    # +2.0 if management ports (SSH/Telnet/Web) are accessible across subnet
    raw_surface = 1.0 + (insecure_services_count * 1.8) + (total_ports * 0.4)
    if any(p in ports_set for p in [22, 23, 80, 443, 8080]):
        raw_surface += 1.5

    attack_surface_score = round(min(10.0, max(0.5, raw_surface)), 1)

    notes = []
    if is_private:
        notes.append("Private RFC 1918 IPv4 address.")
    else:
        notes.append("PUBLIC routable IPv4 address detected! Critical internet exposure.")

    if is_gateway_adjacent:
        notes.append("Co-located on primary default gateway subnet without dedicated IoT VLAN isolation.")
    
    if 23 in ports_set or 554 in ports_set:
        notes.append("High-risk management or streaming ports directly reachable across local subnet.")

    if not notes:
        notes.append("Standard network exposure.")

    return {
        "reachability": "Local Subnet" if is_gateway_adjacent else "Routed Multi-Subnet",
        "is_routed": not is_gateway_adjacent,
        "vlan_id": vlan_status,
        "subnet": subnet,
        "attack_surface_score": attack_surface_score,
        "exposed_ports_count": total_ports,
        "insecure_services_count": insecure_services_count,
        "isolation_recommended": isolation_recommended,
        "notes": " | ".join(notes),
    }
