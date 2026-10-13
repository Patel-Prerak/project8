// Interactive Cyber Network Topology Map Canvas

class NetworkTopologyMap {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.devices = [];
    this.nodes = [];
    this.particles = [];
    this.selectedNode = null;
    this.hoveredNode = null;

    this.resizeCanvas();
    window.addEventListener('resize', () => this.resizeCanvas());

    this.bindEvents();
    this.startAnimationLoop();
  }

  resizeCanvas() {
    if (!this.canvas) return;
    const rect = this.canvas.parentElement.getBoundingClientRect();
    this.canvas.width = rect.width;
    this.canvas.height = 480;
    this.layoutNodes();
  }

  setDevices(devices) {
    this.devices = devices;
    this.layoutNodes();
  }

  layoutNodes() {
    if (!this.canvas) return;
    const w = this.canvas.width;
    const h = this.canvas.height;
    const centerX = w / 2;
    const centerY = h / 2;

    this.nodes = [];

    // Central Gateway Node
    const gatewayNode = {
      id: 'gateway',
      ip: '192.168.137.1',
      label: 'Gateway / Router',
      type: 'gateway',
      x: centerX,
      y: centerY,
      radius: 26,
      color: '#06b6d4',
      riskScore: 0,
      isGateway: true
    };
    this.nodes.push(gatewayNode);

    // Position IoT devices in elliptical orbits around the gateway
    const count = this.devices.length;
    if (count === 0) return;

    const baseRadius = Math.min(w, h) * 0.38;

    this.devices.forEach((dev, idx) => {
      const angle = (idx / count) * (Math.PI * 2) - Math.PI / 2;
      const dist = baseRadius + (idx % 2 === 0 ? -25 : 25);
      const x = centerX + Math.cos(angle) * dist;
      const y = centerY + Math.sin(angle) * dist;

      let color = '#10b981';
      if (dev.is_quarantined) color = '#ec4899';
      else if (dev.risk_level === 'Critical') color = '#ef4444';
      else if (dev.risk_level === 'High') color = '#f97316';
      else if (dev.risk_level === 'Medium') color = '#eab308';

      this.nodes.push({
        id: dev.id,
        ip: dev.ip,
        label: dev.vendor || dev.hostname || dev.ip,
        type: dev.device_type,
        device: dev,
        x: x,
        y: y,
        radius: 18,
        color: color,
        riskScore: dev.risk_score,
        isQuarantined: dev.is_quarantined
      });
    });

    // Seed traffic particles
    this.particles = [];
    for (let i = 0; i < 24; i++) {
      if (this.nodes.length > 1) {
        const targetNode = this.nodes[1 + Math.floor(Math.random() * (this.nodes.length - 1))];
        this.particles.push({
          target: targetNode,
          progress: Math.random(),
          speed: 0.006 + Math.random() * 0.008
        });
      }
    }
  }

  bindEvents() {
    this.canvas.addEventListener('mousemove', (e) => {
      const rect = this.canvas.getBoundingClientRect();
      const mx = e.clientX - rect.left;
      const my = e.clientY - rect.top;

      this.hoveredNode = null;
      for (const node of this.nodes) {
        const dx = node.x - mx;
        const dy = node.y - my;
        if (Math.sqrt(dx * dx + dy * dy) <= node.radius + 6) {
          this.hoveredNode = node;
          this.canvas.style.cursor = 'pointer';
          return;
        }
      }
      this.canvas.style.cursor = 'default';
    });

    this.canvas.addEventListener('click', () => {
      if (this.hoveredNode && !this.hoveredNode.isGateway && this.hoveredNode.device) {
        if (window.openDeviceDossier) {
          window.openDeviceDossier(this.hoveredNode.device.id);
        }
      }
    });
  }

  startAnimationLoop() {
    const render = () => {
      this.draw();
      requestAnimationFrame(render);
    };
    requestAnimationFrame(render);
  }

  draw() {
    if (!this.canvas || !this.ctx) return;
    const ctx = this.ctx;
    const w = this.canvas.width;
    const h = this.canvas.height;

    ctx.clearRect(0, 0, w, h);

    // Draw background grid lines
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.025)';
    ctx.lineWidth = 1;
    for (let x = 0; x < w; x += 40) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, h);
      ctx.stroke();
    }
    for (let y = 0; y < h; y += 40) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }

    if (this.nodes.length === 0) {
      ctx.fillStyle = '#64748b';
      ctx.font = '14px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText('No active IoT assets found. Run network discovery scan to map topology.', w / 2, h / 2);
      return;
    }

    const gateway = this.nodes[0];

    // Draw links from gateway to all IoT nodes
    for (let i = 1; i < this.nodes.length; i++) {
      const node = this.nodes[i];
      ctx.beginPath();
      ctx.moveTo(gateway.x, gateway.y);
      ctx.lineTo(node.x, node.y);

      if (node.isQuarantined) {
        ctx.strokeStyle = 'rgba(236, 72, 153, 0.4)';
        ctx.setLineDash([6, 6]);
      } else {
        ctx.strokeStyle = 'rgba(6, 182, 212, 0.15)';
        ctx.setLineDash([]);
      }
      ctx.lineWidth = 1.5;
      ctx.stroke();
      ctx.setLineDash([]);
    }

    // Animate traffic particles
    for (const p of this.particles) {
      p.progress += p.speed;
      if (p.progress > 1) p.progress = 0;

      const px = gateway.x + (p.target.x - gateway.x) * p.progress;
      const py = gateway.y + (p.target.y - gateway.y) * p.progress;

      ctx.beginPath();
      ctx.arc(px, py, 3, 0, Math.PI * 2);
      ctx.fillStyle = p.target.isQuarantined ? '#ec4899' : '#06b6d4';
      ctx.shadowBlur = 8;
      ctx.shadowColor = ctx.fillStyle;
      ctx.fill();
      ctx.shadowBlur = 0;
    }

    // Draw Nodes
    for (const node of this.nodes) {
      const isHovered = this.hoveredNode === node;

      // Outer glow circle
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.radius + (isHovered ? 8 : 4), 0, Math.PI * 2);
      ctx.fillStyle = node.color + (isHovered ? '44' : '22');
      ctx.fill();

      // Core node body
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
      ctx.fillStyle = '#0f172a';
      ctx.fill();
      ctx.lineWidth = isHovered ? 3 : 2;
      ctx.strokeStyle = node.color;
      ctx.stroke();

      // Node Label
      ctx.fillStyle = '#ffffff';
      ctx.font = '600 11px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(node.ip, node.x, node.y + node.radius + 14);

      ctx.fillStyle = '#94a3b8';
      ctx.font = '10px Inter, sans-serif';
      ctx.fillText(node.label.length > 18 ? node.label.substring(0, 16) + '...' : node.label, node.x, node.y + node.radius + 26);

      // Icon / Glyphs
      ctx.fillStyle = node.color;
      ctx.font = 'bold 10px JetBrains Mono';
      if (node.isGateway) {
        ctx.fillText('GW', node.x, node.y + 4);
      } else if (node.isQuarantined) {
        ctx.fillText('BLCK', node.x, node.y + 4);
      } else {
        ctx.fillText(Math.round(node.riskScore), node.x, node.y + 4);
      }
    }
  }
}
