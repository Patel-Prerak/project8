import sys
import os
import argparse
import uvicorn
import webbrowser
import threading
import time
import socket

BANNER = """
=============================================================================
  ██████╗ ██╗███████╗██╗  ██╗██████╗ ███████╗████████╗███████╗ ██████╗████████╗
  ██╔══██╗██║██╔════╝██║ ██╔╝██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
  ██████╔╝██║███████╗█████╔╝ ██║  ██║█████╗     ██║   █████╗  ██║        ██║   
  ██╔══██╗██║╚════██║██╔═██╗ ██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   
  ██║  ██║██║███████║██║  ██╗██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   
  ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝   
       IoT Security Assessment & Automated Response Platform v2.0
=============================================================================
 [*] Discovery: Multi-Subnet Layer 2 ARP, Layer 3 TCP/ICMP, SSDP, mDNS
 [*] Multi-Layer Assessment: Services | Firmware | CVEs | Config | Exposure | Behavior
 [*] Response Center: Windows/Linux Firewall Isolation & Multi-Vendor Scripts
 [*] Cross-Platform: Windows, Linux, macOS, Docker
=============================================================================
"""

def get_primary_lan_ip() -> str:
    """Finds primary local network IP for displaying in terminal."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def open_browser(port: int):
    time.sleep(1.5)
    try:
        webbrowser.open(f"http://localhost:{port}")
    except Exception:
        pass

def parse_args():
    parser = argparse.ArgumentParser(description="IoT Security Assessment & Response Platform Launcher")
    parser.add_argument(
        "--host",
        default=os.getenv("HOST", "0.0.0.0"),
        help="Host address to bind (default: 0.0.0.0 to allow access from other devices)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("PORT", "8000")),
        help="Port to listen on (default: 8000)"
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        default=os.getenv("NO_BROWSER", "false").lower() in ("true", "1", "yes"),
        help="Do not automatically launch web browser"
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        default=os.getenv("RELOAD", "false").lower() in ("true", "1", "yes"),
        help="Enable uvicorn auto-reload for development"
    )
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    print(BANNER)

    lan_ip = get_primary_lan_ip()
    print(f" [*] Web Platform (Local):   http://127.0.0.1:{args.port}")
    if lan_ip != "127.0.0.1" and args.host in ("0.0.0.0", lan_ip):
        print(f" [*] Web Platform (Network): http://{lan_ip}:{args.port} (Access from other devices)")
    print(f" [*] REST API Documentation: http://127.0.0.1:{args.port}/docs")
    print("=============================================================================\n")

    # Start behavior monitor in background
    try:
        from backend.assessment.behavior_monitor import behavior_monitor
        behavior_monitor.start()
    except Exception as e:
        print(f" [!] Warning: Behavior monitor initialization note: {e}")

    # Launch browser if requested
    if not args.no_browser:
        threading.Thread(target=open_browser, args=(args.port,), daemon=True).start()

    uvicorn.run(
        "backend.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info"
    )
