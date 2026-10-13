// API & WebSocket Communication Layer

const API = {
  baseUrl: window.location.origin,

  async request(endpoint, options = {}) {
    try {
      const response = await fetch(`${this.baseUrl}${endpoint}`, {
        headers: {
          'Content-Type': 'application/json',
          ...(options.headers || {})
        },
        ...options
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ detail: response.statusText }));
        throw new Error(errorData.detail || `Request failed with status ${response.status}`);
      }

      return await response.json();
    } catch (err) {
      console.error(`API Error on ${endpoint}:`, err);
      throw err;
    }
  },

  // System
  getSystemStatus() {
    return this.request('/api/system/status');
  },

  // Discovery
  getInterfaces() {
    return this.request('/api/discovery/interfaces');
  },
  getDiscoveryStatus() {
    return this.request('/api/discovery/status');
  },
  startDiscovery(cidr, scanType = 'FULL') {
    return this.request('/api/discovery/start', {
      method: 'POST',
      body: JSON.stringify({ cidr, scan_type: scanType })
    });
  },

  // Devices
  getDevices(search = '', riskFilter = 'ALL') {
    const params = new URLSearchParams();
    if (search) params.append('search', search);
    if (riskFilter && riskFilter !== 'ALL') params.append('risk_filter', riskFilter);
    return this.request(`/api/devices?${params.toString()}`);
  },
  getDeviceDetail(id) {
    return this.request(`/api/devices/${id}`);
  },
  addCustomDevice(ip, vendor, deviceType) {
    return this.request(`/api/devices?ip=${encodeURIComponent(ip)}&vendor=${encodeURIComponent(vendor)}&device_type=${encodeURIComponent(deviceType)}`, {
      method: 'POST'
    });
  },
  deleteDevice(id) {
    return this.request(`/api/devices/${id}`, { method: 'DELETE' });
  },

  // Assessment
  assessDevice(id) {
    return this.request(`/api/devices/${id}/assess`, { method: 'POST' });
  },
  assessAllDevices() {
    return this.request('/api/devices/assess-all', { method: 'POST' });
  },

  // CVEs
  getCVEs(search = '') {
    const q = search ? `?search=${encodeURIComponent(search)}` : '';
    return this.request(`/api/cve/database${q}`);
  },

  // Behavior & Traffic
  getBehaviorStatus() {
    return this.request('/api/behavior/status');
  },
  startBehaviorMonitor() {
    return this.request('/api/behavior/start', { method: 'POST' });
  },
  stopBehaviorMonitor() {
    return this.request('/api/behavior/stop', { method: 'POST' });
  },
  getBehaviorAnomalies() {
    return this.request('/api/behavior/anomalies');
  },
  simulateAnomaly(ip, anomalyType) {
    return this.request(`/api/behavior/simulate-anomaly?ip=${encodeURIComponent(ip)}&anomaly_type=${encodeURIComponent(anomalyType)}`, {
      method: 'POST'
    });
  },

  // Quarantine
  getQuarantineStatus() {
    return this.request('/api/quarantine/status');
  },
  quarantineDevice(deviceId, reason, method = 'WINDOWS_FIREWALL', adminNotes = '') {
    return this.request('/api/quarantine/isolate', {
      method: 'POST',
      body: JSON.stringify({
        device_id: deviceId,
        reason: reason,
        method: method,
        admin_notes: adminNotes
      })
    });
  },
  releaseDevice(deviceId, reason = 'Released by admin') {
    return this.request('/api/quarantine/release', {
      method: 'POST',
      body: JSON.stringify({
        device_id: deviceId,
        reason: reason
      })
    });
  },
  getIsolationScripts(deviceId) {
    return this.request(`/api/quarantine/${deviceId}/scripts`);
  }
};

// WebSocket Streaming Manager
class RealtimeStream {
  constructor() {
    this.ws = null;
    this.listeners = new Map();
    this.reconnectTimer = null;
  }

  connect() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;

    try {
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        console.log('Realtime WebSocket Connected.');
        this.emit('connection', { status: 'CONNECTED' });
        // Heartbeat
        this.pingInterval = setInterval(() => {
          if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send('ping');
          }
        }, 15000);
      };

      this.ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          this.emit(msg.type, msg.data || msg);
          this.emit('all', msg);
        } catch (e) {
          // Heartbeat pong string
        }
      };

      this.ws.onclose = () => {
        console.warn('Realtime WebSocket closed. Reconnecting in 3s...');
        this.emit('connection', { status: 'DISCONNECTED' });
        clearInterval(this.pingInterval);
        clearTimeout(this.reconnectTimer);
        this.reconnectTimer = setTimeout(() => this.connect(), 3000);
      };

      this.ws.onerror = (err) => {
        console.error('WebSocket Error:', err);
      };
    } catch (err) {
      console.error('Failed to instantiate WebSocket:', err);
    }
  }

  on(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    this.listeners.get(event).push(callback);
  }

  emit(event, data) {
    if (this.listeners.has(event)) {
      this.listeners.get(event).forEach(cb => {
        try { cb(data); } catch (e) { console.error(e); }
      });
    }
  }
}

const socketStream = new RealtimeStream();
socketStream.connect();
