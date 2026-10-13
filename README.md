# IoT Risk Detect & Security Response Platform v2.0

Transforming IoT Risk Detect into an enterprise-grade **IoT Security Assessment, Posture Scoring, and Automated Response Platform**.

The platform discovers, identifies, and assesses connected devices across 6 defense-in-depth security layers, provides explainable mathematical risk scoring (0.0 to 100.0), and enforces immediate network quarantine and multi-vendor firewall isolation.

```
DISCOVER (Layer 2 ARP Sweep + Layer 3 TCP Subnet Sweep + SSDP + mDNS)
  ↓
IDENTIFY (IEEE OUI MAC Vendor + Hostname + NetBIOS + Classification)
  ↓
SECURITY ASSESSMENT (6 Security Dimensions)
  ├── 1. Services Exposure (Insecure / Cleartext Protocol Analysis)
  ├── 2. Firmware & Software (Header Banners + Model Identification)
  ├── 3. CVE Intelligence (Curated IoT Vulnerability Correlation)
  ├── 4. Security Configuration (Auth, Encryption, RTSP, MQTT, Web Banners)
  ├── 5. Network Exposure (Reachability, Gateway Adjacency, Attack Surface)
  └── 6. Traffic & Behavior Monitoring (Port Scan & Flood Anomaly Detection)
  ↓
FINDING CORRELATION & RISK SCORING (0.0 to 100.0)
  ↓
ACTIONABLE RECOMMENDATIONS & EXECUTIVE REPORTING (HTML / PDF / CSV / JSON)
  ↓
AUTOMATED RESPONSE & QUARANTINE (Windows / Linux Kernel Rules & Multi-Vendor Script Export)
```

---

## Ready to Use on Any Device (Cross-Platform)

This application is fully portable and pre-configured to run out-of-the-box on **Windows**, **Linux**, **macOS**, **Raspberry Pi**, and **Docker containers**.

### 1. Windows Quickstart (One-Click)

Simply double-click:
```cmd
start.bat
```
*`start.bat` automatically verifies Python 3.9+, initializes a virtual environment, installs dependencies, and launches the web dashboard.*

Or manually in Command Prompt / PowerShell:
```cmd
python -m pip install -r requirements.txt
python run.py
```

---

### 2. Linux & macOS Quickstart (One-Click)

Open terminal in the project directory:
```bash
chmod +x start.sh
./start.sh
```
*`start.sh` automatically checks Python 3, sets up `.venv`, installs requirements, and launches the platform.*

Or manually in your terminal:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 run.py
```

---

### 3. Docker & Docker Compose (Zero Installation)

For instant deployment without configuring Python locally:

```bash
docker compose up --build -d
```
The platform will compile the lightweight container and expose the dashboard on port `8000`.

> **Note for Linux / Raspberry Pi Docker hosts:** To enable native Layer 2 ARP discovery and packet capture across your physical LAN, uncomment `network_mode: "host"` in `docker-compose.yml`.

---

### 4. Accessing from Other Devices on your Network

By default, the platform binds to `0.0.0.0`, allowing any device on your local Wi-Fi or LAN (laptops, phones, tablets, or workstations) to access the platform:

1. Look at the terminal output when starting the app:
   ```
   [*] Web Platform (Local):   http://127.0.0.1:8000
   [*] Web Platform (Network): http://192.168.1.150:8000 (Access from other devices)
   [*] REST API Documentation: http://127.0.0.1:8000/docs
   ```
2. On any other device connected to the same network, open your web browser and navigate to:
   ```
   http://<HOST-IP>:8000
   ```
   *(Replace `<HOST-IP>` with the network IP printed in the console, e.g. `http://192.168.1.150:8000`)*

---

## Command-Line Configuration Options

`run.py` supports environment variables and command-line arguments:

```bash
python run.py --host 0.0.0.0 --port 8000 --no-browser
```

| Argument | Environment Variable | Default | Description |
| :--- | :--- | :--- | :--- |
| `--host` | `HOST` | `0.0.0.0` | IP interface to bind to (`0.0.0.0` for all LAN access, `127.0.0.1` for local-only) |
| `--port` | `PORT` | `8000` | Port to listen on |
| `--no-browser` | `NO_BROWSER` | `false` | Disable auto-opening the web browser (recommended for Docker & headless servers) |
| `--reload` | `RELOAD` | `false` | Enable live code reloading for development |

---

## Key Capabilities

1. **Multi-Subnet Reconnaissance & Discovery**:
   - Transcends the Layer 2 boundary: combines Layer 2 ARP sweeps on local segments with high-speed non-blocking asynchronous Layer 3 TCP sweeps across routed subnets.
   - Multicast SSDP/UPnP M-SEARCH and mDNS probing for smart TVs, cameras, speakers, and IoT bridges.
   - IEEE OUI vendor database matching thousands of IoT manufacturer prefixes.
   - Cross-platform ARP table parsing (`/proc/net/arp`, `ip neigh`, `arp -a`).

2. **6-Layer In-Depth Security Assessment**:
   - **Services Layer**: Scans and evaluates protocols (Telnet 23, FTP 21, plain HTTP 80/8080, RTSP 554/8554, MQTT 1883, CoAP 5683, UPnP 1900/5000).
   - **Firmware & Model Layer**: Identifies device models, firmware versions, web servers (Boa, RomPager, GoAhead, uHTTPd), and embedded OS (BusyBox, Dropbear).
   - **CVE Assessment**: Matches detected vendor, product, and version against a curated database of 40+ high-severity IoT CVEs with CVSS scores and remediations.
   - **Configuration Audit**: Checks for cleartext management, unauthenticated RTSP surveillance feeds, open anonymous MQTT brokers, and information leakage.
   - **Network Exposure**: Computes attack surface score, subnet routability, and VLAN isolation status.
   - **Behavior Monitoring**: Real-time packet sniffer detecting network reconnaissance (port scans), traffic flood spikes, and suspicious outbound C2 callbacks.

3. **Explainable Risk Correlation & Posture Scoring**:
   - Multi-factor mathematical formula synthesizing findings into a normalized **0.0 - 100.0 Risk Score**:
     - `0.0 - 19.9`: **Low Risk**
     - `20.0 - 44.9`: **Medium Risk**
     - `45.0 - 69.9`: **High Risk**
     - `70.0 - 100.0`: **Critical Risk**
   - Step-by-step prioritized remediation guidance tailored for network administrators.

4. **Automated Response & Device Quarantine**:
   - **Active OS Firewall Isolation**:
     - **Windows**: Directly creates Windows Firewall inbound and outbound blocking rules (`IoT-Quarantine-In-<IP>` and `IoT-Quarantine-Out-<IP>`).
     - **Linux**: Enforces `iptables` kernel drop rules when run with administrative/root privileges, with seamless fallback to application-layer software quarantine.
   - **Multi-Vendor Script Generation**: Generates ready-to-run firewall scripts for:
     - Windows PowerShell (`isolate-<ip>.ps1`)
     - Linux `iptables`
     - Cisco IOS / ASA Access Control Lists (ACL)
     - MikroTik RouterOS filter rules

5. **Executive Security Dossiers & Reporting**:
   - Interactive Canvas Network Topology Map with real-time risk halo indicators and traffic flows.
   - Executive-ready printable HTML security assessment report (print-to-PDF).
   - Full CSV export and JSON machine-readable posture feed.

---

## Project Structure

```
risk detection in iot devices/
├── backend/
│   ├── main.py                     # FastAPI server, WebSocket hub, and REST routes
│   ├── database.py                 # SQLite schema & persistence engine
│   ├── models.py                   # Pydantic data schemas
│   ├── discovery/
│   │   ├── scanner.py              # Cross-platform L2 ARP + L3 TCP multi-subnet scanner
│   │   ├── mdns_ssdp.py            # SSDP M-SEARCH & mDNS prober
│   │   └── fingerprint.py          # OUI MAC vendor lookup & device classifier
│   ├── assessment/
│   │   ├── service_scanner.py      # Async IoT port & service scanner
│   │   ├── banner_grabber.py       # Deep protocol banner grabber (HTTP, RTSP, FTP, MQTT, SSH, Telnet)
│   │   ├── firmware_detector.py    # Firmware, model, and OS signature parser
│   │   ├── cve_engine.py           # IoT CVE vulnerability repository & matcher
│   │   ├── config_auditor.py       # Observable security configuration compliance auditor
│   │   ├── network_exposure.py     # Attack surface & VLAN isolation analyzer
│   │   ├── behavior_monitor.py     # Packet sniffer & anomaly detection engine
│   │   ├── risk_correlator.py      # Multi-layer normalized 0-100 risk scoring
│   │   └── assessment_coordinator.py # Full assessment orchestrator
│   ├── quarantine/
│   │   └── quarantine_manager.py   # Cross-platform Windows/Linux firewall isolation & script generator
│   └── reports/
│       └── report_generator.py     # HTML, CSV, and JSON report generator
├── frontend/
│   ├── index.html                  # Cyber dark theme Single Page Application
│   ├── css/
│   │   └── styles.css              # Glassmorphism, animations, responsive layout
│   └── js/
│       ├── api.js                  # Dynamic REST & WebSocket client
│       ├── app.js                  # UI coordinator, modal manager, and action handlers
│       └── topology.js             # Canvas network topology visualizer
├── data/
│   └── iot_risk.db                 # Persistent SQLite database
├── Dockerfile                      # Multi-arch Linux container definition
├── docker-compose.yml              # 1-command container orchestration
├── .dockerignore                   # Docker context exclusion rules
├── .env.example                    # Template environment variables
├── .gitignore                      # Git exclusion rules
├── requirements.txt                # Pinned Python package dependencies
├── start.bat                       # 1-click Windows startup script
├── start.sh                        # 1-click Linux/macOS startup script
├── run.py                          # Cross-platform launcher CLI
└── README.md                       # Documentation
```

---

## Interactive API Documentation

Once the server is running, interactive OpenAPI/Swagger documentation is available at:
```
http://127.0.0.1:8000/docs
```
Or Redoc documentation at:
```
http://127.0.0.1:8000/redoc
```
