/* ═══════════════════════════════════════════════════════════════
   Ophanim-EDR — Causality Engine Interactive Guide
   Animations, charts, graph visualization, collapsibles
   ═══════════════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {
  initScrollReveal();
  initNavHighlight();
  initHeroGraph();
  initCharts();
  initStatCounters();
});

/* ── Scroll Reveal ────────────────────────────────────────────── */
function initScrollReveal() {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry, i) => {
      if (entry.isIntersecting) {
        setTimeout(() => entry.target.classList.add('visible'), i * 80);
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.1, rootMargin: '0px 0px -50px 0px' });

  document.querySelectorAll('.reveal').forEach(el => observer.observe(el));
}

/* ── Nav Scroll Highlighting ──────────────────────────────────── */
function initNavHighlight() {
  const nav = document.getElementById('nav');
  const links = document.querySelectorAll('.nav-links a');
  const sections = Array.from(links).map(a => document.querySelector(a.getAttribute('href')));

  window.addEventListener('scroll', () => {
    // Shrink nav on scroll
    nav.classList.toggle('scrolled', window.scrollY > 60);

    // Highlight active section
    let current = '';
    sections.forEach(sec => {
      if (sec && sec.offsetTop - 200 <= window.scrollY) {
        current = sec.id;
      }
    });
    links.forEach(a => {
      a.classList.toggle('active', a.getAttribute('href') === `#${current}`);
    });
  });
}

/* ── Collapsible Sections ─────────────────────────────────────── */
function toggleCollapsible(trigger) {
  const body = trigger.nextElementSibling;
  const isOpen = trigger.classList.toggle('open');
  body.classList.toggle('open', isOpen);
}

function toggleStage(el) {
  const detail = el.querySelector('.stage-detail');
  const wasActive = el.classList.contains('active');

  // Close all
  document.querySelectorAll('.pipeline-stage').forEach(s => {
    s.classList.remove('active');
    s.querySelector('.stage-detail').classList.remove('show');
  });

  // Open clicked (if it wasn't already open)
  if (!wasActive) {
    el.classList.add('active');
    detail.classList.add('show');
  }
}

/* ── Hero Animated Graph ──────────────────────────────────────── */
function initHeroGraph() {
  const svg = document.getElementById('graphSvg');
  if (!svg) return;

  const nodes = [
    { id: 0, x: 120, y: 80,  r: 18, type: 'process', label: 'svchost',  color: '#a78bfa' },
    { id: 1, x: 300, y: 60,  r: 14, type: 'file',    label: 'config.ini', color: '#60a5fa' },
    { id: 2, x: 250, y: 180, r: 16, type: 'process', label: 'cmd.exe',  color: '#a78bfa' },
    { id: 3, x: 480, y: 120, r: 14, type: 'socket',  label: '10.0.0.5', color: '#2dd4bf' },
    { id: 4, x: 400, y: 250, r: 15, type: 'file',    label: 'data.db',  color: '#60a5fa' },
    { id: 5, x: 580, y: 200, r: 14, type: 'socket',  label: '203.0.113.1', color: '#fb7185' },
    { id: 6, x: 150, y: 260, r: 13, type: 'file',    label: 'log.txt',  color: '#60a5fa' },
    { id: 7, x: 550, y: 60,  r: 12, type: 'process', label: 'explorer', color: '#a78bfa' },
    { id: 8, x: 80,  y: 170, r: 11, type: 'registry',label: 'HKLM\\Run', color: '#fbbf24' },
  ];

  const edges = [
    { src: 0, dst: 1, type: 'READ',     anom: false },
    { src: 0, dst: 2, type: 'FORK',     anom: false },
    { src: 2, dst: 4, type: 'READ',     anom: false },
    { src: 2, dst: 6, type: 'WRITE',    anom: false },
    { src: 7, dst: 3, type: 'CONNECT',  anom: false },
    { src: 7, dst: 1, type: 'READ',     anom: false },
    { src: 0, dst: 8, type: 'WRITE',    anom: false },
    // Anomalous edges (attack path)
    { src: 2, dst: 5, type: 'CONNECT',  anom: true },
    { src: 2, dst: 3, type: 'SEND',     anom: true },
    { src: 4, dst: 5, type: 'SEND',     anom: true },
  ];

  // Draw edges
  edges.forEach(e => {
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    line.setAttribute('x1', nodes[e.src].x);
    line.setAttribute('y1', nodes[e.src].y);
    line.setAttribute('x2', nodes[e.dst].x);
    line.setAttribute('y2', nodes[e.dst].y);
    line.setAttribute('class', 'edge' + (e.anom ? ' anomalous' : ''));
    svg.appendChild(line);

    // Edge label
    const mx = (nodes[e.src].x + nodes[e.dst].x) / 2;
    const my = (nodes[e.src].y + nodes[e.dst].y) / 2;
    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('x', mx);
    text.setAttribute('y', my - 6);
    text.setAttribute('text-anchor', 'middle');
    text.setAttribute('fill', e.anom ? '#fb7185' : 'rgba(255,255,255,0.2)');
    text.setAttribute('font-size', '9');
    text.setAttribute('font-family', 'Inter, sans-serif');
    text.textContent = e.type;
    svg.appendChild(text);
  });

  // Draw nodes
  nodes.forEach(n => {
    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    g.setAttribute('class', 'node');

    // Glow
    const glow = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    glow.setAttribute('cx', n.x);
    glow.setAttribute('cy', n.y);
    glow.setAttribute('r', n.r + 6);
    glow.setAttribute('fill', n.color);
    glow.setAttribute('opacity', '0.1');
    g.appendChild(glow);

    // Circle
    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', n.x);
    circle.setAttribute('cy', n.y);
    circle.setAttribute('r', n.r);
    circle.setAttribute('fill', 'rgba(0,0,0,0.5)');
    circle.setAttribute('stroke', n.color);
    circle.setAttribute('stroke-width', '2');
    g.appendChild(circle);

    // Type icon
    const icons = { process: '⚙', file: '📄', socket: '🌐', registry: '📋' };
    const icon = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    icon.setAttribute('x', n.x);
    icon.setAttribute('y', n.y + 4);
    icon.setAttribute('text-anchor', 'middle');
    icon.setAttribute('font-size', n.r * 0.8);
    icon.textContent = icons[n.type] || '?';
    g.appendChild(icon);

    // Label
    const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    label.setAttribute('x', n.x);
    label.setAttribute('y', n.y + n.r + 14);
    label.setAttribute('text-anchor', 'middle');
    label.setAttribute('fill', 'rgba(255,255,255,0.5)');
    label.setAttribute('font-size', '10');
    label.setAttribute('font-family', 'Inter, sans-serif');
    label.textContent = n.label;
    g.appendChild(label);

    // Tooltip on hover
    g.addEventListener('mouseenter', () => {
      circle.setAttribute('stroke-width', '3');
      glow.setAttribute('opacity', '0.25');
    });
    g.addEventListener('mouseleave', () => {
      circle.setAttribute('stroke-width', '2');
      glow.setAttribute('opacity', '0.1');
    });

    svg.appendChild(g);
  });
}

/* ── Canvas Charts ────────────────────────────────────────────── */
function initCharts() {
  drawLossChart();
  drawSeparationChart();
}

function drawLossChart() {
  const canvas = document.getElementById('lossChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  canvas.width = canvas.clientWidth * dpr;
  canvas.height = canvas.clientHeight * dpr;
  ctx.scale(dpr, dpr);
  const W = canvas.clientWidth, H = canvas.clientHeight;

  const losses = [1.7358, 1.4383, 1.4122, 1.3963, 1.3869, 1.3822, 1.3765, 1.3732, 1.3681, 1.3619];
  const baseline = Math.log(9); // ~2.197

  const pad = { top: 20, right: 30, bottom: 40, left: 55 };
  const pw = W - pad.left - pad.right;
  const ph = H - pad.top - pad.bottom;
  const yMin = 1.3, yMax = 2.3;

  function xPos(i) { return pad.left + (i / (losses.length - 1)) * pw; }
  function yPos(v) { return pad.top + ((yMax - v) / (yMax - yMin)) * ph; }

  // Grid
  ctx.strokeStyle = 'rgba(255,255,255,0.05)';
  ctx.lineWidth = 1;
  for (let v = 1.4; v <= 2.2; v += 0.2) {
    ctx.beginPath();
    ctx.moveTo(pad.left, yPos(v));
    ctx.lineTo(W - pad.right, yPos(v));
    ctx.stroke();
  }

  // Axes labels
  ctx.fillStyle = 'rgba(255,255,255,0.4)';
  ctx.font = '11px Inter, sans-serif';
  ctx.textAlign = 'right';
  for (let v = 1.4; v <= 2.2; v += 0.2) {
    ctx.fillText(v.toFixed(1), pad.left - 8, yPos(v) + 4);
  }
  ctx.textAlign = 'center';
  for (let i = 0; i < losses.length; i++) {
    ctx.fillText(i + 1, xPos(i), H - pad.bottom + 20);
  }
  ctx.fillText('Epoch', W / 2, H - 5);

  // Baseline (random guessing)
  ctx.strokeStyle = 'rgba(45,212,191,0.3)';
  ctx.setLineDash([6, 4]);
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  ctx.moveTo(pad.left, yPos(baseline));
  ctx.lineTo(W - pad.right, yPos(baseline));
  ctx.stroke();
  ctx.setLineDash([]);

  ctx.fillStyle = 'rgba(45,212,191,0.5)';
  ctx.textAlign = 'left';
  ctx.fillText('Random (ln9 ≈ 2.20)', W - pad.right - 130, yPos(baseline) - 8);

  // Loss line
  const animateLine = () => {
    const observer = new IntersectionObserver((entries) => {
      if (entries[0].isIntersecting) {
        let progress = 0;
        const animate = () => {
          progress = Math.min(progress + 0.03, 1);

          // Clear only the chart area
          ctx.clearRect(pad.left - 2, pad.top - 2, pw + 4, ph + 4);

          // Redraw grid
          ctx.strokeStyle = 'rgba(255,255,255,0.05)';
          ctx.lineWidth = 1;
          for (let v = 1.4; v <= 2.2; v += 0.2) {
            ctx.beginPath();
            ctx.moveTo(pad.left, yPos(v));
            ctx.lineTo(W - pad.right, yPos(v));
            ctx.stroke();
          }

          // Redraw baseline
          ctx.strokeStyle = 'rgba(45,212,191,0.3)';
          ctx.setLineDash([6, 4]);
          ctx.lineWidth = 1.5;
          ctx.beginPath();
          ctx.moveTo(pad.left, yPos(baseline));
          ctx.lineTo(W - pad.right, yPos(baseline));
          ctx.stroke();
          ctx.setLineDash([]);

          // Gradient fill
          const grad = ctx.createLinearGradient(0, pad.top, 0, pad.top + ph);
          grad.addColorStop(0, 'rgba(167,139,250,0.15)');
          grad.addColorStop(1, 'rgba(167,139,250,0)');

          const maxIdx = Math.floor(progress * (losses.length - 1));
          const frac = (progress * (losses.length - 1)) - maxIdx;

          ctx.beginPath();
          ctx.moveTo(xPos(0), yPos(losses[0]));
          for (let i = 1; i <= maxIdx; i++) {
            ctx.lineTo(xPos(i), yPos(losses[i]));
          }
          if (maxIdx < losses.length - 1) {
            const interp = losses[maxIdx] + frac * (losses[maxIdx + 1] - losses[maxIdx]);
            ctx.lineTo(xPos(maxIdx + frac), yPos(interp));
          }

          // Fill area
          const lastX = maxIdx < losses.length - 1 ? xPos(maxIdx + frac) : xPos(maxIdx);
          const lastY = maxIdx < losses.length - 1
            ? yPos(losses[maxIdx] + frac * (losses[maxIdx + 1] - losses[maxIdx]))
            : yPos(losses[maxIdx]);
          ctx.strokeStyle = '#a78bfa';
          ctx.lineWidth = 2.5;
          ctx.stroke();

          ctx.lineTo(lastX, pad.top + ph);
          ctx.lineTo(xPos(0), pad.top + ph);
          ctx.closePath();
          ctx.fillStyle = grad;
          ctx.fill();

          // Data points
          for (let i = 0; i <= maxIdx; i++) {
            ctx.beginPath();
            ctx.arc(xPos(i), yPos(losses[i]), 4, 0, Math.PI * 2);
            ctx.fillStyle = '#a78bfa';
            ctx.fill();
            ctx.strokeStyle = 'rgba(0,0,0,0.5)';
            ctx.lineWidth = 1.5;
            ctx.stroke();
          }

          if (progress < 1) requestAnimationFrame(animate);
        };
        animate();
        observer.unobserve(canvas);
      }
    }, { threshold: 0.5 });
    observer.observe(canvas);
  };
  animateLine();
}

function drawSeparationChart() {
  const canvas = document.getElementById('separationChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  canvas.width = canvas.clientWidth * dpr;
  canvas.height = canvas.clientHeight * dpr;
  ctx.scale(dpr, dpr);
  const W = canvas.clientWidth, H = canvas.clientHeight;

  // Simulated histogram data
  const benignBins = [
    { x: 5, h: 8 }, { x: 8, h: 45 }, { x: 10, h: 140 },
    { x: 12, h: 180 }, { x: 14, h: 90 }, { x: 16, h: 30 }, { x: 18, h: 7 }
  ];
  const attackBins = [
    { x: 110, h: 5 }, { x: 115, h: 15 }, { x: 118, h: 30 },
    { x: 121, h: 25 }, { x: 124, h: 35 }, { x: 127, h: 30 },
    { x: 130, h: 20 }, { x: 133, h: 10 }, { x: 136, h: 5 }
  ];

  const pad = { top: 20, right: 30, bottom: 40, left: 55 };
  const pw = W - pad.left - pad.right;
  const ph = H - pad.top - pad.bottom;

  const xMinAll = 0, xMaxAll = 145;
  const yMaxAll = 200;

  function xP(v) { return pad.left + ((v - xMinAll) / (xMaxAll - xMinAll)) * pw; }
  function yP(v) { return pad.top + ph - (v / yMaxAll) * ph; }

  // Axes
  ctx.fillStyle = 'rgba(255,255,255,0.4)';
  ctx.font = '11px Inter, sans-serif';
  ctx.textAlign = 'center';
  for (let v = 0; v <= 140; v += 20) {
    ctx.fillText(v, xP(v), H - pad.bottom + 18);
  }
  ctx.fillText('Anomaly Score', W / 2, H - 4);
  ctx.textAlign = 'right';
  for (let v = 0; v <= 200; v += 50) {
    ctx.fillText(v, pad.left - 8, yP(v) + 4);
    ctx.strokeStyle = 'rgba(255,255,255,0.05)';
    ctx.beginPath(); ctx.moveTo(pad.left, yP(v)); ctx.lineTo(W - pad.right, yP(v)); ctx.stroke();
  }

  // Gap zone
  ctx.fillStyle = 'rgba(255,255,255,0.02)';
  ctx.fillRect(xP(22), pad.top, xP(108) - xP(22), ph);
  ctx.fillStyle = 'rgba(255,255,255,0.15)';
  ctx.font = '13px Inter, sans-serif';
  ctx.textAlign = 'center';
  ctx.fillText('← Clean separation: 111.53 →', xP(65), pad.top + ph / 2);
  ctx.font = '10px Inter, sans-serif';
  ctx.fillStyle = 'rgba(255,255,255,0.08)';
  ctx.fillText('No overlap', xP(65), pad.top + ph / 2 + 18);

  // Animation
  const observer = new IntersectionObserver((entries) => {
    if (entries[0].isIntersecting) {
      let progress = 0;
      const animate = () => {
        progress = Math.min(progress + 0.025, 1);
        const ease = 1 - Math.pow(1 - progress, 3);

        // Clear bars area
        ctx.clearRect(pad.left, pad.top, pw, ph);

        // Redraw gap zone
        ctx.fillStyle = 'rgba(255,255,255,0.02)';
        ctx.fillRect(xP(22), pad.top, xP(108) - xP(22), ph);
        ctx.fillStyle = 'rgba(255,255,255,0.15)';
        ctx.font = '13px Inter, sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('← Clean separation: 111.53 →', xP(65), pad.top + ph / 2);
        ctx.font = '10px Inter, sans-serif';
        ctx.fillStyle = 'rgba(255,255,255,0.08)';
        ctx.fillText('No overlap', xP(65), pad.top + ph / 2 + 18);

        // Redraw grid
        ctx.strokeStyle = 'rgba(255,255,255,0.05)';
        for (let v = 50; v <= 200; v += 50) {
          ctx.beginPath(); ctx.moveTo(pad.left, yP(v)); ctx.lineTo(W - pad.right, yP(v)); ctx.stroke();
        }

        const barW = pw / ((xMaxAll - xMinAll) / 3) * 0.7;

        // Benign bars
        benignBins.forEach(b => {
          const bh = b.h * ease;
          ctx.fillStyle = 'rgba(96,165,250,0.6)';
          ctx.fillRect(xP(b.x) - barW / 2, yP(bh), barW, yP(0) - yP(bh));
          ctx.strokeStyle = 'rgba(96,165,250,0.8)';
          ctx.lineWidth = 1;
          ctx.strokeRect(xP(b.x) - barW / 2, yP(bh), barW, yP(0) - yP(bh));
        });

        // Attack bars
        attackBins.forEach(b => {
          const bh = b.h * ease;
          ctx.fillStyle = 'rgba(251,113,133,0.6)';
          ctx.fillRect(xP(b.x) - barW / 2, yP(bh), barW, yP(0) - yP(bh));
          ctx.strokeStyle = 'rgba(251,113,133,0.8)';
          ctx.lineWidth = 1;
          ctx.strokeRect(xP(b.x) - barW / 2, yP(bh), barW, yP(0) - yP(bh));
        });

        // Mean lines
        if (ease > 0.5) {
          const alpha = (ease - 0.5) * 2;
          ctx.setLineDash([4, 3]);
          // Benign mean
          ctx.strokeStyle = `rgba(96,165,250,${alpha * 0.8})`;
          ctx.lineWidth = 1.5;
          ctx.beginPath(); ctx.moveTo(xP(12.97), yP(0)); ctx.lineTo(xP(12.97), pad.top); ctx.stroke();
          // Attack mean
          ctx.strokeStyle = `rgba(251,113,133,${alpha * 0.8})`;
          ctx.beginPath(); ctx.moveTo(xP(124.51), yP(0)); ctx.lineTo(xP(124.51), pad.top); ctx.stroke();
          ctx.setLineDash([]);

          // Labels
          ctx.fillStyle = `rgba(96,165,250,${alpha})`;
          ctx.font = '10px Inter, sans-serif';
          ctx.textAlign = 'center';
          ctx.fillText('μ=12.97', xP(12.97), pad.top + 14);
          ctx.fillStyle = `rgba(251,113,133,${alpha})`;
          ctx.fillText('μ=124.51', xP(124.51), pad.top + 14);
        }

        if (progress < 1) requestAnimationFrame(animate);
      };
      animate();
      observer.unobserve(canvas);
    }
  }, { threshold: 0.3 });
  observer.observe(canvas);
}

/* ── Stat Counter Animation ───────────────────────────────────── */
function initStatCounters() {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const el = entry.target;
        el.classList.add('visible');

        const target = parseFloat(el.dataset.target);
        const suffix = el.dataset.suffix || '';
        const decimals = parseInt(el.dataset.decimals || '0');
        const duration = 1500;
        const start = performance.now();

        function tick(now) {
          const elapsed = now - start;
          const progress = Math.min(elapsed / duration, 1);
          const ease = 1 - Math.pow(1 - progress, 3);
          const current = target * ease;

          if (target > 1000) {
            el.textContent = Math.round(current).toLocaleString() + suffix;
          } else {
            el.textContent = current.toFixed(decimals) + suffix;
          }

          if (progress < 1) requestAnimationFrame(tick);
        }
        requestAnimationFrame(tick);
        observer.unobserve(el);
      }
    });
  }, { threshold: 0.5 });

  document.querySelectorAll('[data-animate]').forEach(el => observer.observe(el));
}
