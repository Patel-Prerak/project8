import asyncio
import ssl
import socket
import re
from typing import Dict, Any, Optional

async def grab_http_banner(ip: str, port: int, use_ssl: bool = False, timeout: float = 2.0) -> Dict[str, Any]:
    """Grabs HTTP/HTTPS headers, server tokens, title, and SSL certificate information."""
    result = {
        "server": None,
        "title": None,
        "auth_required": False,
        "headers": {},
        "ssl_info": None,
    }

    try:
        ssl_ctx = None
        if use_ssl:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ssl_ctx),
            timeout=timeout
        )

        # Inspect SSL cert if HTTPS
        if use_ssl:
            try:
                ssl_obj = writer.get_extra_info("ssl_object")
                if ssl_obj:
                    peercert = ssl_obj.getpeercert(binary_form=True)
                    tls_version = ssl_obj.version()
                    cipher = ssl_obj.cipher()
                    # Also try to get decoded cert info if possible
                    cert_dict = ssl_obj.getpeercert()
                    result["ssl_info"] = {
                        "tls_version": tls_version,
                        "cipher": cipher[0] if cipher else None,
                        "is_self_signed": True if not cert_dict else False,
                    }
            except Exception:
                pass

        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {ip}:{port}\r\n"
            f"User-Agent: Mozilla/5.0 (IoT-Security-Auditor/1.0)\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("utf-8")

        writer.write(request)
        await writer.drain()

        response = await asyncio.wait_for(reader.read(4096), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        text = response.decode("utf-8", errors="ignore")
        lines = text.split("\r\n")

        for line in lines:
            if ":" in line:
                k, v = line.split(":", 1)
                k_clean = k.strip().lower()
                v_clean = v.strip()
                result["headers"][k_clean] = v_clean
                if k_clean == "server":
                    result["server"] = v_clean
                elif k_clean == "www-authenticate":
                    result["auth_required"] = True

        # Extract <title>...</title>
        title_match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
        if title_match:
            result["title"] = title_match.group(1).strip()

        # Check HTTP status line
        if lines and ("401 Unauthorized" in lines[0] or "403 Forbidden" in lines[0]):
            result["auth_required"] = True

    except Exception:
        pass

    return result

async def grab_rtsp_banner(ip: str, port: int = 554, timeout: float = 2.0) -> Dict[str, Any]:
    """Probes RTSP service with OPTIONS and DESCRIBE to identify camera server & auth posture."""
    result = {
        "server": None,
        "auth_required": False,
        "public_methods": None,
        "unauthenticated_stream_exposed": False,
    }

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )

        req_options = (
            f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
            f"CSeq: 1\r\n"
            f"User-Agent: IoT-Risk-Detector/1.0\r\n\r\n"
        ).encode("utf-8")

        writer.write(req_options)
        await writer.drain()

        resp = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        text = resp.decode("utf-8", errors="ignore")

        for line in text.split("\r\n"):
            if line.lower().startswith("server:"):
                result["server"] = line.split(":", 1)[1].strip()
            elif line.lower().startswith("public:"):
                result["public_methods"] = line.split(":", 1)[1].strip()

        # Probe DESCRIBE to see if auth is required
        req_describe = (
            f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\n"
            f"CSeq: 2\r\n"
            f"Accept: application/sdp\r\n\r\n"
        ).encode("utf-8")

        writer.write(req_describe)
        await writer.drain()

        desc_resp = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        desc_text = desc_resp.decode("utf-8", errors="ignore")

        if "401 Unauthorized" in desc_text:
            result["auth_required"] = True
        elif "200 OK" in desc_text and ("application/sdp" in desc_text or "m=video" in desc_text):
            result["auth_required"] = False
            result["unauthenticated_stream_exposed"] = True

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except Exception:
        pass

    return result

async def grab_ssh_banner(ip: str, port: int = 22, timeout: float = 2.0) -> Optional[str]:
    """Reads SSH protocol identification string (e.g. SSH-2.0-Dropbear_2020.81)."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        banner = await asyncio.wait_for(reader.readline(), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return banner.decode("utf-8", errors="ignore").strip()
    except Exception:
        return None

async def grab_telnet_banner(ip: str, port: int = 23, timeout: float = 2.0) -> Optional[str]:
    """Reads Telnet initial prompt/banner."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        # Filter non-printable telnet IAC negotiation bytes
        clean = "".join(c for c in data.decode("utf-8", errors="ignore") if 32 <= ord(c) < 127 or c in "\r\n\t")
        return clean.strip() or "Telnet Daemon Active"
    except Exception:
        return None

async def grab_ftp_banner(ip: str, port: int = 21, timeout: float = 2.0) -> Dict[str, Any]:
    """Reads FTP 220 banner and tests for anonymous login."""
    result = {"banner": None, "anonymous_allowed": False}
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        banner = await asyncio.wait_for(reader.readline(), timeout=timeout)
        result["banner"] = banner.decode("utf-8", errors="ignore").strip()

        # Check anonymous login
        writer.write(b"USER anonymous\r\n")
        await writer.drain()
        resp_user = await asyncio.wait_for(reader.readline(), timeout=timeout)

        writer.write(b"PASS anonymous@iot.test\r\n")
        await writer.drain()
        resp_pass = await asyncio.wait_for(reader.readline(), timeout=timeout)

        pass_text = resp_pass.decode("utf-8", errors="ignore")
        if pass_text.startswith("230"):
            result["anonymous_allowed"] = True

        writer.write(b"QUIT\r\n")
        await writer.drain()
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except Exception:
        pass
    return result

async def grab_mqtt_status(ip: str, port: int = 1883, timeout: float = 2.0) -> Dict[str, Any]:
    """Sends MQTT CONNECT packet and tests if unauthenticated connection is accepted."""
    result = {"open_broker": False, "auth_required": True, "details": "Unreachable"}
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        # MQTT 3.1.1 CONNECT packet without username/password
        # Header 0x10, remaining length 0x12 (18 bytes)
        # Protocol: MQTT, Level: 4, Flags: 0x02 (CleanSession), KeepAlive: 60s
        # Client ID: "iotchk"
        packet = b"\x10\x12\x00\x04MQTT\x04\x02\x00<\x00\x06iotchk"
        writer.write(packet)
        await writer.drain()

        resp = await asyncio.wait_for(reader.read(4), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        if len(resp) >= 4 and resp[0] == 0x20: # CONNACK
            return_code = resp[3]
            if return_code == 0:
                result["open_broker"] = True
                result["auth_required"] = False
                result["details"] = "Unauthenticated MQTT connection accepted"
            elif return_code in [4, 5]: # Bad user/pass or Not authorized
                result["auth_required"] = True
                result["details"] = "Authentication required (User/Pass Enforced)"
    except Exception:
        pass
    return result
