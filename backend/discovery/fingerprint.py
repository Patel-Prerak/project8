import socket
import struct
import re
from typing import Tuple, Optional, Dict, Any

# Extensive OUI Vendor Mapping for IoT and Networking Hardware
OUI_TABLE: Dict[str, str] = {
    # IoT Microcontrollers & Modules
    "18:FE:34": "Espressif Systems (ESP8266/ESP32)",
    "24:0A:C4": "Espressif Systems (ESP32)",
    "24:62:AB": "Espressif Systems (ESP32)",
    "24:6F:28": "Espressif Systems (ESP32)",
    "24:B2:DE": "Espressif Systems (ESP32)",
    "30:AE:A4": "Espressif Systems (ESP32)",
    "3C:61:05": "Espressif Systems (ESP32)",
    "3C:71:BF": "Espressif Systems (ESP32)",
    "4C:11:AE": "Espressif Systems (ESP32)",
    "5C:CF:7F": "Espressif Systems (ESP8266)",
    "60:01:94": "Espressif Systems (ESP8266)",
    "68:C6:3A": "Espressif Systems (ESP32)",
    "84:0D:8E": "Espressif Systems (ESP32)",
    "84:F3:EB": "Espressif Systems (ESP8266)",
    "8C:AA:B5": "Espressif Systems (ESP32)",
    "94:B9:7E": "Espressif Systems (ESP32)",
    "A4:CF:12": "Espressif Systems (ESP32)",
    "AC:D0:74": "Espressif Systems (ESP32)",
    "B4:E6:2D": "Espressif Systems (ESP32)",
    "C4:4F:33": "Espressif Systems (ESP8266)",
    "CC:50:E3": "Espressif Systems (ESP32)",
    "DC:4F:22": "Espressif Systems (ESP32)",
    "E0:98:06": "Espressif Systems (ESP32)",
    "EC:FA:BC": "Espressif Systems (ESP8266)",

    # Raspberry Pi
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading",
    "E4:5F:01": "Raspberry Pi Trading",
    "28:CD:C1": "Raspberry Pi Trading",
    "D8:3A:DD": "Raspberry Pi Trading",

    # Tuya Smart & OEM Smart Home
    "10:D5:61": "Tuya Smart Inc.",
    "50:8A:06": "Tuya Smart Inc.",
    "68:57:2D": "Tuya Smart Inc.",
    "70:89:76": "Tuya Smart Inc.",
    "7C:F6:66": "Tuya Smart Inc.",
    "A0:92:08": "Tuya Smart Inc.",
    "D4:A6:51": "Tuya Smart Inc.",
    "78:0F:77": "Tuya Smart Inc.",
    "14:24:D3": "Tuya Smart Inc.",

    # IP Cameras / CCTV
    "00:12:12": "Hikvision Digital Technology",
    "00:40:48": "Hikvision Digital Technology",
    "10:12:FB": "Hikvision Digital Technology",
    "28:57:BE": "Hikvision Digital Technology",
    "44:19:B6": "Hikvision Digital Technology",
    "44:A6:42": "Hikvision Digital Technology",
    "54:C4:15": "Hikvision Digital Technology",
    "BC:5E:97": "Hikvision Digital Technology",
    "C0:56:E3": "Hikvision Digital Technology",
    "38:71:DE": "Dahua Technology",
    "3C:EF:8C": "Dahua Technology",
    "40:24:B2": "Dahua Technology",
    "48:E2:44": "Dahua Technology",
    "90:02:A9": "Dahua Technology",
    "E0:50:8B": "Dahua Technology",
    "00:40:8C": "Axis Communications (IP Cameras)",
    "AC:CC:8E": "Axis Communications",
    "00:0F:7D": "Foscam Digital Technology",
    "00:62:6E": "Amcrest Technologies",
    "2C:AA:8E": "Wyze Labs Inc.",
    "00:80:F0": "Panasonic Surveillance",
    "00:0B:82": "Grandstream Networks",

    # Smart Home / Hubs / Audio
    "00:17:88": "Philips Lighting (Hue)",
    "EC:B5:FA": "Philips Lighting (Hue)",
    "00:0E:58": "Sonos Inc.",
    "48:A6:B8": "Sonos Inc.",
    "5C:AA:FD": "Sonos Inc.",
    "94:9F:3E": "Sonos Inc.",
    "B8:E9:37": "Sonos Inc.",
    "00:11:32": "Synology Inc. (NAS)",
    "00:08:9B": "QNAP Systems Inc. (NAS)",
    "24:4B:FE": "Amazon Technologies (Echo/Kindle/FireTV)",
    "44:65:0D": "Amazon Technologies",
    "68:37:E9": "Amazon Technologies",
    "68:54:5A": "Amazon Technologies",
    "74:75:48": "Amazon Technologies",
    "AC:63:BE": "Amazon Technologies",
    "FC:65:DE": "Amazon Technologies",
    "FC:A1:83": "Amazon Technologies",
    "3C:5A:37": "Google (Nest/Chromecast)",
    "48:D6:D5": "Google (Nest/Home)",
    "54:60:09": "Google (Nest/Home)",
    "D8:6C:63": "Google LLC",
    "F4:F5:D8": "Google LLC",
    "F8:0F:F9": "Google LLC",
    "00:09:B0": "Onkyo Corporation",
    "00:05:CD": "Denon / Marantz",

    # Networking & Gateways
    "00:1A:2B": "Ayecom Technology",
    "00:1D:AA": "TP-Link Corporation",
    "14:CF:92": "TP-Link Corporation",
    "1C:3B:F3": "TP-Link Corporation",
    "50:C7:BF": "TP-Link Corporation (Tapo/Kasa)",
    "60:32:B1": "TP-Link Corporation",
    "70:4F:57": "TP-Link Corporation",
    "98:48:27": "TP-Link Corporation",
    "A0:F3:C1": "TP-Link Corporation",
    "C0:25:E9": "TP-Link Corporation",
    "C4:6E:1F": "TP-Link Corporation",
    "E8:48:B8": "TP-Link Corporation",
    "00:09:5B": "Netgear Inc.",
    "00:14:6C": "Netgear Inc.",
    "00:1F:33": "Netgear Inc.",
    "00:26:F2": "Netgear Inc.",
    "20:4E:7F": "Netgear Inc.",
    "A0:04:60": "Netgear Inc.",
    "00:18:E7": "Cameo Communications / D-Link",
    "00:05:5D": "D-Link International",
    "14:D6:4D": "D-Link International",
    "28:10:7B": "D-Link International",
    "00:0C:42": "MikroTik",
    "08:55:31": "MikroTik",
    "18:FD:74": "MikroTik",
    "48:8F:5A": "MikroTik",
    "64:D1:54": "MikroTik",
    "B8:69:F4": "MikroTik",
    "C4:AD:34": "MikroTik",
    "00:27:22": "Ubiquiti Networks",
    "04:18:D6": "Ubiquiti Networks",
    "24:A4:3C": "Ubiquiti Networks",
    "68:D7:9A": "Ubiquiti Networks",
    "78:8A:20": "Ubiquiti Networks",
    "80:2A:A8": "Ubiquiti Networks",
    "AC:8B:A9": "Ubiquiti Networks",
    "B4:FB:E4": "Ubiquiti Networks",
    "DC:9F:DB": "Ubiquiti Networks",
    "F0:9F:C2": "Ubiquiti Networks",
    "00:1C:10": "Cisco Systems",
    "00:1E:13": "Cisco Systems",
    "00:24:14": "Cisco Systems",
    "58:97:BD": "Cisco Systems",
    "70:81:05": "Cisco Systems",
    "A0:EC:F9": "Cisco Systems",

    # Smart TV / Appliances
    "00:12:47": "Samsung Electronics",
    "00:16:32": "Samsung Electronics",
    "00:21:D1": "Samsung Electronics",
    "00:26:37": "Samsung Electronics",
    "40:16:3B": "Samsung Electronics (Smart TV)",
    "50:85:69": "Samsung Electronics",
    "64:1C:AE": "Samsung Electronics",
    "A8:7B:39": "Samsung Electronics",
    "B4:79:A7": "Samsung Electronics",
    "00:1C:62": "LG Electronics",
    "10:F9:6F": "LG Electronics",
    "20:3D:66": "LG Electronics (webOS TV)",
    "58:A2:B5": "LG Electronics",
    "64:99:5D": "LG Electronics",
    "74:40:BE": "LG Electronics",
    "A8:23:FE": "LG Electronics",
    "00:09:DF": "Sony Corporation (Bravia)",
    "00:1D:BA": "Sony Interactive (PlayStation)",
    "00:24:8D": "Sony Interactive (PlayStation)",
    "2C:CC:44": "Roku Inc.",
    "84:EA:99": "Roku Inc.",
    "B0:EE:45": "Roku Inc.",
    "D8:31:34": "Roku Inc.",

    # Mobile / PC / Workstations
    "00:1C:42": "Parallels / Apple",
    "3C:06:30": "Apple Inc.",
    "40:6c:8f": "Apple Inc.",
    "50:bc:96": "Apple Inc.",
    "60:fa:cd": "Apple Inc.",
    "70:3e:ac": "Apple Inc.",
    "78:4f:43": "Apple Inc.",
    "80:e6:50": "Apple Inc.",
    "88:66:a5": "Apple Inc.",
    "a4:83:e7": "Apple Inc.",
    "ac:bc:32": "Apple Inc.",
    "bc:d0:74": "Apple Inc.",
    "e0:b9:ba": "Apple Inc.",
    "00:50:56": "VMware Inc.",
    "08:00:27": "Oracle VirtualBox",
    "00:15:5D": "Microsoft Hyper-V",
    "00:1A:11": "Google Inc.",
    "00:1A:79": "Alcatel-Lucent",
    "00:1B:FC": "ASUSTeK Computer",
    "04:D4:C4": "ASUSTeK Computer",
    "00:24:D7": "Intel Corporate",
    "00:1E:67": "Intel Corporate",
    "60:6C:66": "Intel Corporate",
    "84:4B:F5": "Intel Corporate",
    "A4:BB:6D": "Intel Corporate",
    "00:1A:A0": "Dell Inc.",
    "18:03:73": "Dell Inc.",
    "00:1E:0B": "HP Inc.",
    "3C:D9:2B": "HP Inc.",
    "F4:39:09": "HP Inc. (Printer)",
}

def lookup_vendor_by_mac(mac: Optional[str]) -> str:
    if not mac:
        return "Unknown"
    # Normalize MAC to AA:BB:CC:DD:EE:FF
    cleaned = mac.strip().upper().replace("-", ":")
    parts = cleaned.split(":")
    if len(parts) >= 3:
        prefix = ":".join(parts[:3])
        if prefix in OUI_TABLE:
            return OUI_TABLE[prefix]
        # Try checking lower case
        for k, v in OUI_TABLE.items():
            if k.upper() == prefix:
                return v
    return "Unknown Device Vendor"

def resolve_hostname(ip: str, timeout: float = 0.2) -> Optional[str]:
    # Fast NetBIOS node query on UDP 137
    nb_name = query_netbios_name(ip, timeout=timeout)
    if nb_name:
        return nb_name
    return None

def query_netbios_name(ip: str, timeout: float = 0.5) -> Optional[str]:
    """Send NetBIOS Node Status query to UDP port 137"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        # Standard NetBIOS node status request
        # Transaction ID (2 bytes) + Flags (2 bytes) + Questions (2 bytes) + Answer RRs (2 bytes) + ...
        # Name: CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (wildcard *)
        query = (
            b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
            b"\x00\x21\x00\x01"
        )
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if len(data) > 56:
            num_names = data[56]
            if num_names > 0 and len(data) >= 57 + 18:
                # First name is 15 bytes ASCII + 1 byte type
                raw_name = data[57:57+15].decode("ascii", errors="ignore").strip()
                if raw_name:
                    return raw_name
    except Exception:
        pass
    return None

def classify_device(vendor: str, hostname: Optional[str], open_ports: list, banners: list) -> str:
    """Classifies device into specific IoT or enterprise categories based on evidence."""
    blob = f"{vendor} {hostname or ''} {' '.join(str(p) for p in open_ports)} {' '.join(banners)}".lower()

    # IP Cameras
    if any(k in blob for k in ["hikvision", "dahua", "axis", "foscam", "amcrest", "wyze", "reolink", "onvif", "cam", "ipcamera", "rtsp", "surveillance"]):
        return "IP Camera / Surveillance"
    if 554 in open_ports or 8554 in open_ports:
        return "IP Camera / Video Streamer"

    # Smart Speakers / Audio
    if any(k in blob for k in ["sonos", "echo", "alexa", "google home", "nest audio", "homepod", "spotify", "airplay"]):
        return "Smart Speaker / Audio"

    # Smart Lighting & Plugs
    if any(k in blob for k in ["philips hue", "signify", "tapo", "kasa", "tuya", "smart plug", "smart bulb", "wemo", "yeelight", "shelly", "lifx"]):
        return "Smart Lighting / Plug"

    # Microcontroller IoT (ESP32/ESP8266/Raspberry Pi)
    if any(k in blob for k in ["espressif", "esp32", "esp8266", "nodemcu", "raspberry", "raspi"]):
        return "IoT Controller / Sensor"

    # Smart TV / Streaming
    if any(k in blob for k in ["roku", "smart tv", "bravia", "webos", "tizen", "chromecast", "fire tv", "apple tv"]):
        return "Smart TV / Media Player"

    # Router & Gateway
    if any(k in blob for k in ["router", "gateway", "mikrotik", "ubiquiti", "unifi", "pfsense", "opnsense", "openwrt", "dd-wrt", "asuswrt", "tp-link router"]):
        return "Router / Gateway"
    if 53 in open_ports and (80 in open_ports or 443 in open_ports) and not (any(k in blob for k in ["windows", "macintosh"])):
        return "Router / Gateway"

    # Network Storage (NAS)
    if any(k in blob for k in ["synology", "qnap", "truenas", "freenas", "diskstation"]):
        return "Network Attached Storage (NAS)"

    # Printer
    if any(k in blob for k in ["printer", "laserjet", "officejet", "epson", "brother", "xerox", "canon"]) or 9100 in open_ports or 515 in open_ports or 631 in open_ports:
        return "Network Printer"

    # Workstation / PC
    if any(k in blob for k in ["windows", "macintosh", "desktop", "laptop", "ubuntu desktop"]):
        return "Workstation / PC"

    # Default IoT vs Generic
    if 1883 in open_ports or 8883 in open_ports or 5683 in open_ports:
        return "IoT Telemetry Node (MQTT/CoAP)"

    return "Generic IoT Device"
