from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime

class ServiceModel(BaseModel):
    id: Optional[int] = None
    device_id: Optional[int] = None
    port: int
    protocol: str = "TCP"
    service_name: Optional[str] = "Unknown"
    banner: Optional[str] = None
    is_insecure: bool = False
    auth_required: bool = True
    details: Optional[Dict[str, Any]] = None

class VulnerabilityModel(BaseModel):
    id: Optional[int] = None
    device_id: Optional[int] = None
    cve_id: str
    title: str
    description: Optional[str] = None
    severity: str  # Critical, High, Medium, Low
    cvss_score: float = 0.0
    affected_component: Optional[str] = None
    remediation: Optional[str] = None
    reference_url: Optional[str] = None

class ConfigCheckModel(BaseModel):
    id: Optional[int] = None
    device_id: Optional[int] = None
    check_id: str
    category: str
    title: str
    description: Optional[str] = None
    status: str  # PASS, FAIL, WARN
    severity: str  # Critical, High, Medium, Low
    recommendation: Optional[str] = None
    details: Optional[str] = None

class ExposureMetricsModel(BaseModel):
    device_id: Optional[int] = None
    reachability: str = "Local Subnet"
    is_routed: bool = False
    vlan_id: Optional[str] = "Default (VLAN 1)"
    subnet: Optional[str] = None
    attack_surface_score: float = 0.0
    exposed_ports_count: int = 0
    insecure_services_count: int = 0
    notes: Optional[str] = None

class BehaviorEventModel(BaseModel):
    id: Optional[int] = None
    device_id: Optional[int] = None
    device_ip: str
    event_type: str
    severity: str
    title: str
    details: Optional[str] = None
    timestamp: Optional[str] = None

class RiskBreakdown(BaseModel):
    service_risk: float = 0.0
    cve_risk: float = 0.0
    config_risk: float = 0.0
    exposure_risk: float = 0.0
    behavior_risk: float = 0.0
    total_score: float = 0.0
    risk_level: str = "Low"
    recommendations: List[str] = []

class DeviceModel(BaseModel):
    id: Optional[int] = None
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = "Unknown"
    device_type: Optional[str] = "Generic IoT"
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    os_info: Optional[str] = None
    status: str = "Active"
    is_quarantined: bool = False
    risk_score: float = 0.0
    risk_level: str = "Low"
    risk_breakdown: Optional[Dict[str, Any]] = None
    last_seen: Optional[str] = None

class DeviceDetailModel(DeviceModel):
    services: List[ServiceModel] = []
    vulnerabilities: List[VulnerabilityModel] = []
    config_checks: List[ConfigCheckModel] = []
    exposure: Optional[ExposureMetricsModel] = None
    behavior_events: List[BehaviorEventModel] = []
    quarantine_history: List[Dict[str, Any]] = []

class ScanRequest(BaseModel):
    cidr: Optional[str] = None
    scan_type: str = "FULL"  # "ARP", "TCP_SWEEP", "DISCOVERY", "FULL"
    port_range: Optional[str] = "common"  # "common", "iot", "full"

class QuarantineRequest(BaseModel):
    device_id: int
    reason: str
    method: Optional[str] = "WINDOWS_FIREWALL"
    admin_notes: Optional[str] = None

class ReleaseRequest(BaseModel):
    device_id: int
    reason: Optional[str] = "Remediated by administrator"

class CVEEntry(BaseModel):
    cve_id: str
    vendor: str
    product: str
    version_pattern: Optional[str] = None
    title: str
    description: str
    cvss_score: float
    severity: str
    affected_ports: Optional[str] = None
    remediation: str
    reference_url: Optional[str] = None
