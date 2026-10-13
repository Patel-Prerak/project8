import re
from typing import Dict, Any, Optional

def extract_firmware_and_model(
    vendor_hint: str,
    server_banner: Optional[str] = None,
    html_title: Optional[str] = None,
    ssh_banner: Optional[str] = None,
    rtsp_server: Optional[str] = None,
    upnp_meta: Optional[Dict[str, str]] = None
) -> Dict[str, Optional[str]]:
    """Synthesizes vendor, hardware model, software/firmware version, and embedded OS from observations."""
    detected = {
        "vendor": vendor_hint if vendor_hint and vendor_hint != "Unknown" else None,
        "model": None,
        "firmware_version": None,
        "os_info": None,
        "web_server": server_banner,
    }

    # If UPnP metadata already has confirmed details
    if upnp_meta:
        if upnp_meta.get("manufacturer") and not detected["vendor"]:
            detected["vendor"] = upnp_meta["manufacturer"]
        if upnp_meta.get("model"):
            detected["model"] = upnp_meta["model"]

    # 1. Analyze HTML Title
    if html_title:
        title_str = html_title.strip()
        # Hikvision models: DS-2CD..., DS-76...
        m = re.search(r"(DS-[0-9A-Z\-]+)", title_str)
        if m:
            detected["model"] = m.group(1)
            detected["vendor"] = "Hikvision"

        # Dahua models: DH-IPC..., NVR...
        m = re.search(r"(DH-[0-9A-Z\-]+|IPC-[0-9A-Z\-]+)", title_str)
        if m:
            detected["model"] = m.group(1)
            detected["vendor"] = "Dahua Technology"

        # TP-Link models: Archer ..., TL-WR..., Tapo ...
        m = re.search(r"(Archer\s+[A-Za-z0-9]+|TL-[A-Za-z0-9\-]+|Tapo\s+[A-Za-z0-9]+)", title_str, re.IGNORECASE)
        if m:
            detected["model"] = m.group(1)
            detected["vendor"] = "TP-Link"

        # Netgear models: R7000, Nighthawk ..., WNDR...
        m = re.search(r"(R[0-9]{4}|Nighthawk\s+[A-Za-z0-9]+|WNDR[0-9]+)", title_str, re.IGNORECASE)
        if m:
            detected["model"] = m.group(1)
            detected["vendor"] = "Netgear"

        # D-Link models: DIR-..., DCS-...
        m = re.search(r"(DIR-[0-9A-Za-z]+|DCS-[0-9A-Za-z]+)", title_str, re.IGNORECASE)
        if m:
            detected["model"] = m.group(1)
            detected["vendor"] = "D-Link"

    # 2. Extract Firmware Version from Title or Banners
    combined_text = f"{html_title or ''} {server_banner or ''} {rtsp_server or ''}"
    
    # Version pattern: v1.2.3 or 1.2.3.4 or Build 210901 or 5.4.5_build170123
    v_match = re.search(r"(?:v|ver|version|firmware\s*version[:\s]*)(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9_\-\.]+)?|\d{6,8})", combined_text, re.IGNORECASE)
    if v_match:
        detected["firmware_version"] = v_match.group(1)

    # 3. Analyze SSH Banner (BusyBox, Dropbear, OpenSSH, Raspbian)
    if ssh_banner:
        if "dropbear" in ssh_banner.lower():
            m_db = re.search(r"dropbear[_\s\-]?([0-9\.]+)", ssh_banner, re.IGNORECASE)
            detected["os_info"] = "Embedded Linux (Dropbear SSH)"
            if m_db and not detected["firmware_version"]:
                detected["firmware_version"] = f"Dropbear {m_db.group(1)}"
        elif "raspbian" in ssh_banner.lower() or "debian" in ssh_banner.lower():
            detected["os_info"] = "Raspberry Pi OS (Debian/Linux)"
            detected["vendor"] = detected["vendor"] or "Raspberry Pi Foundation"
        elif "openssh" in ssh_banner.lower():
            m_ssh = re.search(r"OpenSSH[_\s\-]?([0-9\.]+[a-zA-Z0-9]*)", ssh_banner)
            detected["os_info"] = f"Linux ({m_ssh.group(0) if m_ssh else 'OpenSSH'})"

    # 4. Analyze Server Header (Embedded Webservers common on IoT devices)
    if server_banner:
        sb_low = server_banner.lower()
        if "boa" in sb_low:
            detected["os_info"] = detected["os_info"] or "Embedded Linux (Boa Web Server)"
        elif "goahead" in sb_low:
            detected["os_info"] = detected["os_info"] or "Embedded RTOS / Linux (GoAhead)"
        elif "rompager" in sb_low:
            detected["os_info"] = detected["os_info"] or "Allegro RomPager Embedded OS"
        elif "uhttpd" in sb_low:
            detected["os_info"] = detected["os_info"] or "OpenWrt / Embedded Linux (uHTTPd)"
        elif "mini_httpd" in sb_low:
            detected["os_info"] = detected["os_info"] or "Embedded Linux (mini_httpd)"

    # Fallback vendor if still None
    if not detected["vendor"]:
        detected["vendor"] = "Generic IoT Vendor"

    return detected
