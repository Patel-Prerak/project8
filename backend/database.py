import sqlite3
import json
import os
from typing import Dict, List, Optional, Any
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "iot_risk.db")

def get_db_connection() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE NOT NULL,
        mac TEXT,
        hostname TEXT,
        vendor TEXT DEFAULT 'Unknown',
        device_type TEXT DEFAULT 'Generic IoT',
        model TEXT,
        firmware_version TEXT,
        os_info TEXT,
        status TEXT DEFAULT 'Active',
        is_quarantined INTEGER DEFAULT 0,
        risk_score REAL DEFAULT 0.0,
        risk_level TEXT DEFAULT 'Low',
        risk_breakdown TEXT, -- JSON
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS services (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL,
        port INTEGER NOT NULL,
        protocol TEXT NOT NULL,
        service_name TEXT,
        banner TEXT,
        is_insecure INTEGER DEFAULT 0,
        auth_required INTEGER DEFAULT 1,
        details TEXT, -- JSON
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE,
        UNIQUE(device_id, port, protocol)
    );

    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL,
        cve_id TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        severity TEXT NOT NULL,
        cvss_score REAL DEFAULT 0.0,
        affected_component TEXT,
        remediation TEXT,
        reference_url TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE,
        UNIQUE(device_id, cve_id)
    );

    CREATE TABLE IF NOT EXISTS config_checks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL,
        check_id TEXT NOT NULL,
        category TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        status TEXT NOT NULL, -- PASS, FAIL, WARN
        severity TEXT NOT NULL, -- Critical, High, Medium, Low
        recommendation TEXT,
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE,
        UNIQUE(device_id, check_id)
    );

    CREATE TABLE IF NOT EXISTS exposure_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER UNIQUE NOT NULL,
        reachability TEXT DEFAULT 'Local Subnet',
        is_routed INTEGER DEFAULT 0,
        vlan_id TEXT,
        subnet TEXT,
        attack_surface_score REAL DEFAULT 0.0,
        exposed_ports_count INTEGER DEFAULT 0,
        insecure_services_count INTEGER DEFAULT 0,
        notes TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS behavior_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER,
        device_ip TEXT,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        details TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS traffic_stats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER,
        device_ip TEXT NOT NULL,
        packets_in INTEGER DEFAULT 0,
        packets_out INTEGER DEFAULT 0,
        bytes_in INTEGER DEFAULT 0,
        bytes_out INTEGER DEFAULT 0,
        active_conns INTEGER DEFAULT 0,
        top_destinations TEXT, -- JSON
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS quarantine_records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL,
        ip TEXT NOT NULL,
        mac TEXT,
        action TEXT NOT NULL, -- QUARANTINED or RELEASED
        method TEXT NOT NULL, -- WINDOWS_FIREWALL, SOFTWARE_BLOCK, ROUTE_BLACKHOLE
        reason TEXT,
        rule_name TEXT,
        enforced INTEGER DEFAULT 1,
        admin_notes TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS scan_jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_cidr TEXT NOT NULL,
        scan_type TEXT NOT NULL,
        status TEXT DEFAULT 'PENDING', -- PENDING, RUNNING, COMPLETED, FAILED
        progress INTEGER DEFAULT 0,
        total_hosts INTEGER DEFAULT 0,
        found_hosts INTEGER DEFAULT 0,
        started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP,
        error TEXT
    );

    CREATE TABLE IF NOT EXISTS cve_knowledge_base (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cve_id TEXT UNIQUE NOT NULL,
        vendor TEXT NOT NULL,
        product TEXT NOT NULL,
        version_pattern TEXT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        cvss_score REAL NOT NULL,
        severity TEXT NOT NULL,
        affected_ports TEXT,
        remediation TEXT NOT NULL,
        reference_url TEXT
    );
    """)

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully at:", DB_PATH)
