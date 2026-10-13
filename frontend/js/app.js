// Main Application Logic & UI State Controller

let currentView = 'dashboard';
let topologyMapInstance = null;
let activeModalDeviceId = null;

// Initialize app when DOM is loaded
document.addEventListener('DOMContentLoaded', async () => {
  initNavigation();
  initModals();
  initWebSocketHandlers();
  
  // Initial data loads
  await loadSystemStatus();
  await loadInterfaces();
  await refreshDashboard();

  // Initialize Topology Map
  topologyMapInstance = new NetworkTopologyMap('topology-canvas');

  // Auto-refresh stats every 8 seconds
  setInterval(async () => {
    if (currentView === 'dashboard') {
      await refreshDashboard(false);
    } else if (currentView === 'devices') {
      await loadDevices(false);
    } else if (currentView === 'behavior') {
      await loadBehaviorData();
    } else if (currentView === 'quarantine') {
      await loadQuarantineData();
    }
  }, 8000);
});

// ----------------- TOAST NOTIFICATIONS ----------------- //

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `
    <div style="flex-grow:1;">${message}</div>
    <span style="cursor:pointer;opacity:0.6;font-size:16px;" onclick="this.parentElement.remove()">✕</span>
  `;

  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 4500);
}

// ----------------- NAVIGATION ----------------- //

function initNavigation() {
  const navItems = document.querySelectorAll('.nav-item');
  navItems.forEach(item => {
    item.addEventListener('click', (e) => {
      e.preventDefault();
      const targetView = item.getAttribute('data-view');
      switchView(targetView);
    });
  });
}

function switchView(viewName) {
  currentView = viewName;

  // Update nav link active state
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.getAttribute('data-view') === viewName);
  });

  // Update view visibility
  document.querySelectorAll('.view-section').forEach(el => {
    el.classList.toggle('active', el.id === `view-${viewName}`);
  });

  // Update Top Bar Title
  const titles = {
    dashboard: 'Executive Posture & Security Dashboard',
    discovery: 'Network Discovery & Host Reconnaissance',
    devices: 'IoT Asset Inventory & Multi-Layer Assessment',
    cve: 'IoT Vulnerability Intelligence & CVE Registry',
    config: 'Security Configuration & Compliance Audit',
    behavior: 'Traffic Analysis & Anomaly Detection',
    quarantine: 'Automated Quarantine & Incident Response Center',
    topology: 'Visual Network Segmentation & Topology Map',
    reports: 'Audit Reports & Security Export Center'
  };
  document.getElementById('top-bar-title').innerText = titles[viewName] || 'IoT Risk Assessment';

  // Specific view loaders
  if (viewName === 'dashboard') refreshDashboard();
  if (viewName === 'devices') loadDevices();
  if (viewName === 'cve') loadCVEs();
  if (viewName === 'config') loadConfigCompliance();
  if (viewName === 'behavior') loadBehaviorData();
  if (viewName === 'quarantine') loadQuarantineData();
  if (viewName === 'topology') {
    API.getDevices().then(devices => {
      if (topologyMapInstance) {
        topologyMapInstance.resizeCanvas();
        topologyMapInstance.setDevices(devices);
      }
    });
  }
}

// ----------------- SYSTEM STATUS & WEBSOCKET ----------------- //

async function loadSystemStatus() {
  try {
    const sys = await API.getSystemStatus();
    const adminPill = document.getElementById('status-firewall');
    if (adminPill) {
      adminPill.innerHTML = sys.admin_privileges 
        ? `<span class="status-dot"></span> Kernel Firewall (Admin)`
        : `<span class="status-dot" style="background:#f59e0b;box-shadow:0 0 8px #f59e0b;"></span> Elevated Dispatch Mode`;
    }
  } catch (err) {
    console.error(err);
  }
}

function initWebSocketHandlers() {
  socketStream.on('connection', ({ status }) => {
    const wsPill = document.getElementById('status-ws');
    if (wsPill) {
      wsPill.innerHTML = status === 'CONNECTED'
        ? `<span class="status-dot active-pulsing"></span> Live Stream Active`
        : `<span class="status-dot" style="background:#ef4444;box-shadow:0 0 8px #ef4444;"></span> Stream Reconnecting`;
    }
  });

  socketStream.on('DISCOVERY_UPDATE', (data) => {
    const pBar = document.getElementById('discovery-progress-bar');
    const pText = document.getElementById('discovery-status-text');
    if (pBar) pBar.style.width = `${data.progress || 0}%`;
    if (pText) pText.innerText = `${data.message || ''} (${data.found_count || 0} hosts found)`;

    if (data.status === 'COMPLETED') {
      showToast(data.message || 'Discovery scan completed!', 'success');
      loadDevices();
      refreshDashboard();
    }
  });

  socketStream.on('ASSESSMENT_COMPLETED', (data) => {
    showToast(`Multi-layer assessment completed for device #${data.device_id}`, 'success');
    if (activeModalDeviceId === data.device_id) {
      window.openDeviceDossier(data.device_id);
    }
    loadDevices(false);
    refreshDashboard(false);
  });

  socketStream.on('ANOMALY_ALERT', (data) => {
    showToast(`⚠️ [Traffic Anomaly] ${data.title} on ${data.ip}`, 'danger');
    if (currentView === 'behavior') loadBehaviorData();
    refreshDashboard(false);
  });

  socketStream.on('DEVICE_QUARANTINED', (data) => {
    showToast(`🛡️ Device quarantined successfully: ${data.data?.message || ''}`, 'danger');
    loadDevices(false);
    loadQuarantineData();
    refreshDashboard(false);
  });

  socketStream.on('DEVICE_RELEASED', (data) => {
    showToast(`Device released from quarantine: ${data.data?.message || ''}`, 'success');
    loadDevices(false);
    loadQuarantineData();
    refreshDashboard(false);
  });
}

// ----------------- DASHBOARD VIEW ----------------- //

async function refreshDashboard(showToasts = true) {
  try {
    const devices = await API.getDevices();
    const anomalies = await API.getBehaviorAnomalies();
    const quarantine = await API.getQuarantineStatus();

    // Stats KPIs
    const totalCount = devices.length;
    const critCount = devices.filter(d => d.risk_level === 'Critical').length;
    const highCount = devices.filter(d => d.risk_level === 'High').length;
    const quarantinedCount = quarantine.active_quarantined_count || 0;
    const insecureServicesCount = devices.reduce((acc, d) => acc + (d.insecure_services_count || 0), 0);

    const avgRisk = totalCount > 0 ? (devices.reduce((acc, d) => acc + (d.risk_score || 0), 0) / totalCount).toFixed(1) : '0.0';

    document.getElementById('dash-total-devices').innerText = totalCount;
    document.getElementById('dash-crit-devices').innerText = critCount;
    document.getElementById('dash-high-devices').innerText = highCount;
    document.getElementById('dash-quarantined').innerText = quarantinedCount;
    document.getElementById('dash-insecure-services').innerText = insecureServicesCount;
    document.getElementById('dash-avg-score').innerText = `${avgRisk}/100`;

    // High Risk Priority Feed
    const prioContainer = document.getElementById('dash-high-risk-list');
    if (prioContainer) {
      const highPrioDevices = devices.filter(d => d.risk_score >= 45).slice(0, 5);
      if (highPrioDevices.length === 0) {
        prioContainer.innerHTML = `<div style="color:var(--text-dim);padding:14px;text-align:center;">No high or critical risk devices detected. Posture is secure.</div>`;
      } else {
        prioContainer.innerHTML = highPrioDevices.map(d => `
          <div style="display:flex;align-items:center;justify-content:space-between;padding:12px 14px;background:rgba(255,255,255,0.02);border:1px solid var(--border-subtle);border-radius:var(--radius-md);margin-bottom:8px;">
            <div>
              <div style="font-weight:700;font-family:monospace;color:#fff;">${d.ip}</div>
              <div style="font-size:12px;color:var(--text-muted);">${d.vendor} - ${d.device_type}</div>
            </div>
            <div style="display:flex;align-items:center;gap:10px;">
              <span class="badge ${d.risk_level === 'Critical' ? 'badge-critical' : 'badge-high'}">${d.risk_score} ${d.risk_level}</span>
              ${d.is_quarantined ? `<span class="badge badge-quarantined">QUARANTINED</span>` : `<button class="btn btn-danger btn-sm" onclick="promptQuarantine(${d.id}, '${d.ip}')">Quarantine</button>`}
              <button class="btn btn-secondary btn-sm" onclick="openDeviceDossier(${d.id})">Dossier</button>
            </div>
          </div>
        `).join('');
      }
    }

    // Recent Anomaly Alerts Feed
    const anomalyContainer = document.getElementById('dash-anomalies-list');
    if (anomalyContainer) {
      if (anomalies.length === 0) {
        anomalyContainer.innerHTML = `<div style="color:var(--text-dim);padding:14px;text-align:center;">No traffic anomalies detected in recent flow logs.</div>`;
      } else {
        anomalyContainer.innerHTML = anomalies.slice(0, 5).map(a => `
          <div style="padding:10px 14px;background:rgba(239,68,68,0.05);border-left:3px solid var(--risk-critical);border-radius:var(--radius-sm);margin-bottom:8px;">
            <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px;">
              <span style="font-weight:700;color:var(--risk-critical);">${a.title}</span>
              <span style="font-family:monospace;color:var(--text-dim);">${a.device_ip}</span>
            </div>
            <div style="font-size:11.5px;color:var(--text-muted);">${a.details}</div>
          </div>
        `).join('');
      }
    }

  } catch (err) {
    console.error(err);
  }
}

// ----------------- DISCOVERY VIEW ----------------- //

async function loadInterfaces() {
  try {
    const ifaces = await API.getInterfaces();
    const sel = document.getElementById('discovery-interface-select');
    if (!sel) return;

    sel.innerHTML = ifaces.map(i => `
      <option value="${i.cidr}">
        ${i.name} - ${i.ip} (${i.cidr}) [${i.host_count} hosts]
      </option>
    `).join('') + `<option value="CUSTOM">Custom CIDR Range...</option>`;

    sel.addEventListener('change', () => {
      const customInput = document.getElementById('discovery-custom-cidr-group');
      if (customInput) customInput.style.display = sel.value === 'CUSTOM' ? 'block' : 'none';
    });
  } catch (err) {
    console.error(err);
  }
}

async function triggerDiscovery() {
  const sel = document.getElementById('discovery-interface-select');
  const customCidr = document.getElementById('discovery-custom-cidr');
  const scanTypeSel = document.getElementById('discovery-type-select');

  let targetCidr = sel.value === 'CUSTOM' ? (customCidr.value.trim() || '192.168.137.0/24') : sel.value;
  const scanType = scanTypeSel ? scanTypeSel.value : 'FULL';

  try {
    const res = await API.startDiscovery(targetCidr, scanType);
    showToast(res.message, 'info');

    const pBar = document.getElementById('discovery-progress-bar');
    const pText = document.getElementById('discovery-status-text');
    if (pBar) pBar.style.width = '10%';
    if (pText) pText.innerText = `Scan initiated on ${targetCidr}...`;
  } catch (err) {
    showToast(err.message, 'danger');
  }
}

// ----------------- DEVICES VIEW ----------------- //

async function loadDevices(showSpinner = true) {
  const searchInput = document.getElementById('device-search-input');
  const filterSelect = document.getElementById('device-risk-filter');
  const tbody = document.getElementById('devices-table-body');
  if (!tbody) return;

  const search = searchInput ? searchInput.value.trim() : '';
  const filter = filterSelect ? filterSelect.value : 'ALL';

  try {
    const devices = await API.getDevices(search, filter);
    if (devices.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align:center;padding:32px;color:var(--text-dim);">No devices match the criteria. Run a discovery scan or add an IP.</td></tr>`;
      return;
    }

    tbody.innerHTML = devices.map(d => {
      let riskBadgeClass = 'badge-low';
      if (d.risk_level === 'Critical') riskBadgeClass = 'badge-critical';
      else if (d.risk_level === 'High') riskBadgeClass = 'badge-high';
      else if (d.risk_level === 'Medium') riskBadgeClass = 'badge-medium';

      const quarantineBadge = d.is_quarantined 
        ? `<span class="badge badge-quarantined">QUARANTINED</span>`
        : `<span class="badge badge-low">NORMAL</span>`;

      return `
        <tr>
          <td>
            <div style="font-weight:700;font-family:monospace;color:#fff;">${d.ip}</div>
            <div style="font-size:11px;color:var(--text-dim);font-family:monospace;">${d.mac || 'N/A'}</div>
          </td>
          <td>
            <div style="font-weight:600;color:#fff;">${d.vendor || 'Unknown'}</div>
            <div style="font-size:11.5px;color:var(--text-muted);">${d.device_type}</div>
          </td>
          <td>
            <div style="font-size:12px;color:#fff;">${d.model || 'Unknown Model'}</div>
            <div style="font-size:11px;color:var(--text-dim);">${d.firmware_version || 'FW Unknown'}</div>
          </td>
          <td>
            <span class="badge ${d.insecure_services_count > 0 ? 'badge-high' : 'badge-cyan'}">
              ${d.services_count} Ports (${d.insecure_services_count} Insecure)
            </span>
          </td>
          <td>
            ${d.cve_count > 0 ? `<span class="badge badge-critical">${d.cve_count} Vulnerabilities</span>` : `<span class="badge badge-low">0 Flaws</span>`}
          </td>
          <td>
            <span class="badge ${riskBadgeClass}">${d.risk_score} - ${d.risk_level}</span>
          </td>
          <td>${quarantineBadge}</td>
          <td>
            <div style="display:flex;gap:6px;">
              <button class="btn btn-outline-cyan btn-sm" onclick="runSingleDeviceAssess(${d.id})">Assess</button>
              <button class="btn btn-secondary btn-sm" onclick="openDeviceDossier(${d.id})">Dossier</button>
              ${d.is_quarantined 
                ? `<button class="btn btn-secondary btn-sm" onclick="releaseQuarantine(${d.id})">Release</button>`
                : `<button class="btn btn-danger btn-sm" onclick="promptQuarantine(${d.id}, '${d.ip}')">Quarantine</button>`
              }
            </div>
          </td>
        </tr>
      `;
    }).join('');

  } catch (err) {
    console.error(err);
  }
}

async function runSingleDeviceAssess(deviceId) {
  showToast(`Initiating multi-layer assessment for device #${deviceId}...`, 'info');
  try {
    await API.assessDevice(deviceId);
  } catch (err) {
    showToast(err.message, 'danger');
  }
}

async function triggerAssessAll() {
  showToast('Starting sequential multi-layer security assessment for all devices...', 'info');
  try {
    const res = await API.assessAllDevices();
    showToast(res.message, 'success');
  } catch (err) {
    showToast(err.message, 'danger');
  }
}

// ----------------- DOSSIER MODAL ----------------- //

function initModals() {
  document.querySelectorAll('.modal-tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      document.querySelectorAll('.modal-tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.dossier-tab-content').forEach(c => c.style.display = 'none');
      btn.classList.add('active');
      const targetEl = document.getElementById(`dossier-tab-${targetTab}`);
      if (targetEl) targetEl.style.display = 'block';
    });
  });
}

window.openDeviceDossier = async function(deviceId) {
  activeModalDeviceId = deviceId;
  const modal = document.getElementById('device-dossier-modal');
  if (!modal) return;

  modal.classList.add('active');
  document.getElementById('dossier-modal-ip').innerText = `Loading device #${deviceId}...`;

  try {
    const d = await API.getDeviceDetail(deviceId);

    document.getElementById('dossier-modal-ip').innerText = `${d.ip} (${d.vendor} - ${d.device_type})`;
    document.getElementById('dossier-mac').innerText = d.mac || 'N/A';
    document.getElementById('dossier-model').innerText = d.model || 'Unknown Model';
    document.getElementById('dossier-firmware').innerText = d.firmware_version || 'Not Detected';
    document.getElementById('dossier-os').innerText = d.os_info || 'Unknown OS';

    const riskBadge = document.getElementById('dossier-risk-badge');
    riskBadge.innerText = `${d.risk_score} - ${d.risk_level} Risk`;
    riskBadge.className = `badge ${d.risk_level === 'Critical' ? 'badge-critical' : d.risk_level === 'High' ? 'badge-high' : d.risk_level === 'Medium' ? 'badge-medium' : 'badge-low'}`;

    // Quarantine Toggle Button in Modal
    const quarBtn = document.getElementById('dossier-quarantine-toggle-btn');
    if (quarBtn) {
      if (d.is_quarantined) {
        quarBtn.className = 'btn btn-secondary btn-sm';
        quarBtn.innerText = 'Lift Quarantine';
        quarBtn.onclick = () => releaseQuarantine(d.id);
      } else {
        quarBtn.className = 'btn btn-danger btn-sm';
        quarBtn.innerText = 'Quarantine Device';
        quarBtn.onclick = () => promptQuarantine(d.id, d.ip);
      }
    }

    // Tab 1: Services
    const sTable = document.getElementById('dossier-services-table');
    if (sTable) {
      sTable.innerHTML = d.services.length === 0 
        ? `<tr><td colspan="5" style="text-align:center;padding:20px;color:var(--text-dim);">No open ports detected.</td></tr>`
        : d.services.map(s => `
          <tr>
            <td style="font-weight:700;font-family:monospace;color:#fff;">${s.port}</td>
            <td style="font-weight:600;">${s.service_name}</td>
            <td>${s.is_insecure ? `<span class="badge badge-critical">Insecure / Cleartext</span>` : `<span class="badge badge-low">Secure</span>`}</td>
            <td style="font-size:12px;font-family:monospace;color:#38bdf8;">${s.banner || 'None'}</td>
            <td>${s.auth_required ? `<span class="badge badge-low">Enforced</span>` : `<span class="badge badge-critical">Open / None</span>`}</td>
          </tr>
        `).join('');
    }

    // Tab 2: CVEs
    const cveContainer = document.getElementById('dossier-cves-list');
    if (cveContainer) {
      cveContainer.innerHTML = d.vulnerabilities.length === 0
        ? `<div style="padding:20px;text-align:center;color:var(--risk-low);font-weight:600;">✓ No confirmed CVEs matched against detected firmware and services.</div>`
        : d.vulnerabilities.map(v => `
          <div style="background:rgba(239,68,68,0.06);border:1px solid var(--risk-critical-border);border-radius:var(--radius-md);padding:14px;margin-bottom:10px;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
              <span style="font-weight:800;font-family:monospace;color:var(--risk-critical);font-size:14px;">${v.cve_id}</span>
              <span class="badge badge-critical">CVSS ${v.cvss_score} - ${v.severity}</span>
            </div>
            <div style="font-weight:600;color:#fff;margin-bottom:4px;">${v.title}</div>
            <div style="font-size:12px;color:var(--text-muted);margin-bottom:8px;">${v.description}</div>
            <div style="font-size:12px;color:#10b981;background:rgba(16,185,129,0.1);padding:8px;border-radius:4px;">
              <b>Remediation:</b> ${v.remediation}
            </div>
          </div>
        `).join('');
    }

    // Tab 3: Config Checks
    const cfgContainer = document.getElementById('dossier-config-list');
    if (cfgContainer) {
      cfgContainer.innerHTML = d.config_checks.length === 0
        ? `<div style="padding:20px;text-align:center;color:var(--text-dim);">No configuration checks generated yet. Run assessment.</div>`
        : d.config_checks.map(c => `
          <div style="display:flex;justify-content:space-between;align-items:center;padding:12px;background:rgba(255,255,255,0.02);border:1px solid var(--border-subtle);border-radius:var(--radius-md);margin-bottom:8px;">
            <div>
              <div style="font-weight:600;color:#fff;">${c.title}</div>
              <div style="font-size:11.5px;color:var(--text-muted);">${c.description}</div>
              <div style="font-size:11px;color:#38bdf8;margin-top:2px;"><b>Guidance:</b> ${c.recommendation}</div>
            </div>
            <div>
              <span class="badge ${c.status === 'FAIL' ? 'badge-critical' : c.status === 'WARN' ? 'badge-high' : 'badge-low'}">${c.status}</span>
            </div>
          </div>
        `).join('');
    }

    // Tab 4: Network Exposure
    const expContainer = document.getElementById('dossier-exposure-info');
    if (expContainer) {
      const exp = d.exposure || {};
      expContainer.innerHTML = `
        <div class="grid-cols-3" style="margin-bottom:16px;">
          <div class="card" style="padding:14px;">
            <div class="stat-label">Reachability</div>
            <div style="font-size:18px;font-weight:700;color:#fff;">${exp.reachability || 'Local Subnet'}</div>
          </div>
          <div class="card" style="padding:14px;">
            <div class="stat-label">VLAN & Subnet</div>
            <div style="font-size:18px;font-weight:700;color:#fff;">${exp.vlan_id || 'VLAN 1'}</div>
          </div>
          <div class="card" style="padding:14px;">
            <div class="stat-label">Attack Surface Score</div>
            <div style="font-size:18px;font-weight:700;color:var(--risk-high);">${exp.attack_surface_score || '0.0'}/10.0</div>
          </div>
        </div>
        <div style="font-size:12.5px;color:var(--text-muted);background:rgba(0,0,0,0.3);padding:12px;border-radius:6px;border:1px solid var(--border-subtle);">
          <b>Exposure Audit Notes:</b> ${exp.notes || 'No security notes recorded.'}
        </div>
      `;
    }

    // Tab 5: Behavior Profile
    const behContainer = document.getElementById('dossier-behavior-info');
    if (behContainer) {
      const tp = d.traffic_profile || {};
      behContainer.innerHTML = `
        <div class="grid-cols-4" style="margin-bottom:16px;">
          <div class="card" style="padding:14px;"><div class="stat-label">Packets In</div><div style="font-size:18px;font-weight:700;color:#fff;">${tp.packets_in || 0}</div></div>
          <div class="card" style="padding:14px;"><div class="stat-label">Packets Out</div><div style="font-size:18px;font-weight:700;color:#fff;">${tp.packets_out || 0}</div></div>
          <div class="card" style="padding:14px;"><div class="stat-label">Bandwidth</div><div style="font-size:18px;font-weight:700;color:#fff;">${tp.bandwidth_kb || 0} KB</div></div>
          <div class="card" style="padding:14px;"><div class="stat-label">Destinations</div><div style="font-size:18px;font-weight:700;color:#fff;">${tp.active_destinations_count || 0} Peers</div></div>
        </div>
        <h4 style="font-size:13px;margin-bottom:8px;color:#fff;">Behavioral Anomaly History</h4>
        ${d.behavior_events.length === 0 ? `<div style="color:var(--text-dim);font-size:12px;">No historical anomalies logged for this device.</div>` : d.behavior_events.map(e => `
          <div style="padding:8px 12px;background:rgba(239,68,68,0.08);border-radius:4px;margin-bottom:6px;font-size:12px;">
            <b>${e.title}</b> (${e.timestamp}): ${e.details}
          </div>
        `).join('')}
      `;
    }

    // Tab 6: Isolation Scripts
    const scriptContainer = document.getElementById('dossier-scripts-box');
    if (scriptContainer) {
      const scripts = await API.getIsolationScripts(deviceId);
      scriptContainer.innerHTML = `
        <div style="margin-bottom:12px;">
          <h4 style="font-size:13px;color:#fff;margin-bottom:4px;">Windows PowerShell Firewall Script</h4>
          <div class="code-block-box">
            <button class="copy-btn" onclick="copyToClipboard(this)">Copy</button>
            <pre>${scripts.scripts.powershell}</pre>
          </div>
        </div>
        <div style="margin-bottom:12px;">
          <h4 style="font-size:13px;color:#fff;margin-bottom:4px;">Linux iptables Quarantine Script</h4>
          <div class="code-block-box">
            <button class="copy-btn" onclick="copyToClipboard(this)">Copy</button>
            <pre>${scripts.scripts.linux_iptables}</pre>
          </div>
        </div>
        <div>
          <h4 style="font-size:13px;color:#fff;margin-bottom:4px;">Cisco ACL / MikroTik Command</h4>
          <div class="code-block-box">
            <button class="copy-btn" onclick="copyToClipboard(this)">Copy</button>
            <pre>${scripts.scripts.cisco_acl}\n\n${scripts.scripts.mikrotik}</pre>
          </div>
        </div>
      `;
    }

  } catch (err) {
    showToast(err.message, 'danger');
  }
};

function closeDossierModal() {
  const modal = document.getElementById('device-dossier-modal');
  if (modal) modal.classList.remove('active');
  activeModalDeviceId = null;
}

// ----------------- QUARANTINE MODAL & ACTIONS ----------------- //

let targetQuarantineDeviceId = null;

function promptQuarantine(deviceId, ip) {
  targetQuarantineDeviceId = deviceId;
  const modal = document.getElementById('quarantine-confirm-modal');
  if (!modal) return;

  document.getElementById('quarantine-target-ip').innerText = ip;
  document.getElementById('quarantine-reason-input').value = 'High IoT risk score & confirmed vulnerabilities detected';
  modal.classList.add('active');
}

function closeQuarantineModal() {
  const modal = document.getElementById('quarantine-confirm-modal');
  if (modal) modal.classList.remove('active');
  targetQuarantineDeviceId = null;
}

async function executeQuarantine() {
  if (!targetQuarantineDeviceId) return;
  const reason = document.getElementById('quarantine-reason-input').value.trim() || 'Automated security response isolation';

  try {
    const res = await API.quarantineDevice(targetQuarantineDeviceId, reason);
    closeQuarantineModal();
    showToast(`Quarantine action executed: ${res.message}`, 'success');
  } catch (err) {
    showToast(err.message, 'danger');
  }
}

async function releaseQuarantine(deviceId) {
  try {
    const res = await API.releaseDevice(deviceId);
    showToast(res.message, 'success');
  } catch (err) {
    showToast(err.message, 'danger');
  }
}

async function loadQuarantineData() {
  const tbody = document.getElementById('quarantine-table-body');
  const auditBody = document.getElementById('quarantine-audit-body');
  if (!tbody) return;

  try {
    const qData = await API.getQuarantineStatus();
    const active = qData.active_quarantined_devices || [];
    const audit = qData.quarantine_audit_logs || [];

    tbody.innerHTML = active.length === 0
      ? `<tr><td colspan="6" style="text-align:center;padding:28px;color:var(--text-dim);">No devices currently quarantined. Network state is clear.</td></tr>`
      : active.map(d => `
        <tr>
          <td style="font-weight:700;font-family:monospace;color:#fff;">${d.ip}</td>
          <td><b>${d.vendor}</b> (${d.device_type})</td>
          <td><span class="badge badge-critical">${d.risk_score} - ${d.risk_level}</span></td>
          <td><span class="badge badge-quarantined">ACTIVE ISOLATION</span></td>
          <td style="font-size:12px;color:var(--text-muted);">${d.updated_at}</td>
          <td>
            <button class="btn btn-secondary btn-sm" onclick="releaseQuarantine(${d.id})">Lift Quarantine</button>
          </td>
        </tr>
      `).join('');

    if (auditBody) {
      auditBody.innerHTML = audit.length === 0
        ? `<tr><td colspan="5" style="text-align:center;padding:20px;color:var(--text-dim);">No quarantine events recorded yet.</td></tr>`
        : audit.map(a => `
          <tr>
            <td style="font-family:monospace;">${a.timestamp}</td>
            <td style="font-family:monospace;font-weight:600;">${a.ip}</td>
            <td><span class="badge ${a.action === 'QUARANTINED' ? 'badge-critical' : 'badge-low'}">${a.action}</span></td>
            <td style="font-size:12px;">${a.method}</td>
            <td style="font-size:12px;color:var(--text-muted);">${a.reason || 'N/A'}</td>
          </tr>
        `).join('');
    }
  } catch (err) {
    console.error(err);
  }
}

// ----------------- CVE VIEW ----------------- //

async function loadCVEs() {
  const container = document.getElementById('cve-cards-container');
  const searchInput = document.getElementById('cve-search-input');
  if (!container) return;

  const search = searchInput ? searchInput.value.trim() : '';

  try {
    const cves = await API.getCVEs(search);
    container.innerHTML = cves.length === 0
      ? `<div style="color:var(--text-dim);padding:30px;text-align:center;">No CVEs found matching the filter.</div>`
      : cves.map(c => `
        <div class="card" style="margin-bottom:14px;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
            <div style="display:flex;align-items:center;gap:10px;">
              <span style="font-family:monospace;font-weight:800;color:var(--risk-critical);font-size:15px;">${c.cve_id}</span>
              <span class="badge badge-critical">CVSS ${c.cvss_score} - ${c.severity}</span>
            </div>
            <span class="badge badge-cyan">${c.vendor}</span>
          </div>
          <h4 style="font-size:15px;color:#fff;margin-bottom:6px;">${c.title}</h4>
          <p style="font-size:13px;color:var(--text-muted);margin-bottom:10px;line-height:1.5;">${c.description}</p>
          <div style="background:rgba(16,185,129,0.08);border-left:3px solid var(--risk-low);padding:10px 14px;border-radius:4px;font-size:12px;color:#fff;">
            <b>Remediation Guidance:</b> ${c.remediation}
          </div>
        </div>
      `).join('');
  } catch (err) {
    console.error(err);
  }
}

// ----------------- CONFIG COMPLIANCE VIEW ----------------- //

async function loadConfigCompliance() {
  const container = document.getElementById('config-checks-summary-container');
  if (!container) return;

  try {
    const devices = await API.getDevices();
    let totalChecks = 0;
    let failedChecks = 0;
    let warnChecks = 0;
    let passChecks = 0;

    const allChecks = [];
    for (const d of devices) {
      const detail = await API.getDeviceDetail(d.id);
      detail.config_checks.forEach(c => {
        allChecks.push({ ...c, device_ip: d.ip, vendor: d.vendor });
        totalChecks++;
        if (c.status === 'FAIL') failedChecks++;
        else if (c.status === 'WARN') warnChecks++;
        else passChecks++;
      });
    }

    document.getElementById('cfg-stat-total').innerText = totalChecks;
    document.getElementById('cfg-stat-fail').innerText = failedChecks;
    document.getElementById('cfg-stat-warn').innerText = warnChecks;
    document.getElementById('cfg-stat-pass').innerText = passChecks;

    container.innerHTML = allChecks.length === 0
      ? `<div style="text-align:center;padding:24px;color:var(--text-dim);">No configuration audits recorded. Run assessment on devices.</div>`
      : allChecks.map(c => `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:14px;background:var(--bg-card);border:1px solid var(--border-subtle);border-radius:var(--radius-md);margin-bottom:10px;">
          <div>
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">
              <span style="font-weight:700;color:#fff;">${c.title}</span>
              <span class="badge ${c.status === 'FAIL' ? 'badge-critical' : c.status === 'WARN' ? 'badge-high' : 'badge-low'}">${c.status}</span>
              <span style="font-family:monospace;font-size:11px;color:#38bdf8;">[Target: ${c.device_ip}]</span>
            </div>
            <div style="font-size:12.5px;color:var(--text-muted);">${c.description}</div>
            <div style="font-size:12px;color:#10b981;margin-top:4px;"><b>Remediation:</b> ${c.recommendation}</div>
          </div>
          <span class="badge badge-cyan">${c.category}</span>
        </div>
      `).join('');

  } catch (err) {
    console.error(err);
  }
}

// ----------------- BEHAVIOR & TRAFFIC VIEW ----------------- //

async function loadBehaviorData() {
  const anomaliesList = document.getElementById('behavior-anomalies-table');
  const monitorStatusPill = document.getElementById('behavior-monitor-status-text');

  try {
    const status = await API.getBehaviorStatus();
    if (monitorStatusPill) {
      monitorStatusPill.innerText = status.is_running ? 'Active Sniffing' : 'Stopped';
    }

    const anomalies = await API.getBehaviorAnomalies();
    if (anomaliesList) {
      anomaliesList.innerHTML = anomalies.length === 0
        ? `<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--text-dim);">No anomalies detected. Traffic signatures are normal.</td></tr>`
        : anomalies.map(a => `
          <tr>
            <td style="font-family:monospace;font-size:12px;">${a.timestamp}</td>
            <td style="font-family:monospace;font-weight:700;color:#fff;">${a.device_ip}</td>
            <td><span class="badge ${a.severity === 'Critical' ? 'badge-critical' : 'badge-high'}">${a.event_type}</span></td>
            <td style="font-weight:600;color:#fff;">${a.title}</td>
            <td style="font-size:12px;color:var(--text-muted);">${a.details}</td>
          </tr>
        `).join('');
    }
  } catch (err) {
    console.error(err);
  }
}

async function toggleBehaviorMonitor() {
  try {
    const status = await API.getBehaviorStatus();
    if (status.is_running) {
      await API.stopBehaviorMonitor();
      showToast('Behavior traffic sniffer stopped.', 'warning');
    } else {
      await API.startBehaviorMonitor();
      showToast('Behavior traffic sniffer started in background.', 'success');
    }
    loadBehaviorData();
  } catch (err) {
    showToast(err.message, 'danger');
  }
}

async function triggerSimulateAnomaly(anomalyType) {
  const ip = prompt('Enter Device IP to simulate anomaly on:', '192.168.137.100');
  if (!ip) return;

  try {
    const res = await API.simulateAnomaly(ip, anomalyType);
    showToast(`Simulated ${anomalyType} on ${ip}! Alert triggered.`, 'danger');
    loadBehaviorData();
  } catch (err) {
    showToast(err.message, 'danger');
  }
}

// ----------------- UTILITIES ----------------- //

function copyToClipboard(button) {
  const pre = button.parentElement.querySelector('pre');
  if (pre) {
    navigator.clipboard.writeText(pre.innerText).then(() => {
      button.innerText = 'Copied!';
      setTimeout(() => button.innerText = 'Copy', 2000);
    });
  }
}

async function downloadReport(format) {
  if (format === 'html') {
    window.open('/api/reports/html', '_blank');
  } else if (format === 'csv') {
    window.location.href = '/api/reports/csv';
  } else if (format === 'json') {
    window.open('/api/reports/json', '_blank');
  }
}
