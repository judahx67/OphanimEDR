// Provenance Graph Engine - Vanilla JS SVG Renderer
// Supports: rendering, highlighting, step-by-step scenarios, dependency explosion demo

class ProvenanceGraph {
  constructor() {
    this.nodes = new Map();
    this.edges = new Map();
    this.nodeTypes = {
      process:  { color: '#e07b39', shape: 'circle' },
      file:     { color: '#3a7fc1', shape: 'rect' },
      socket:   { color: '#2e9e5b', shape: 'diamond' },
      registry: { color: '#7c4db8', shape: 'hexagon' },
      memory:   { color: '#c4383a', shape: 'circle' },
      pipe:     { color: '#888888', shape: 'diamond' }
    };
  }

  addNode(id, label, type, x, y) {
    this.nodes.set(id, { id, label, type, x, y });
  }

  addEdge(src, dst, type, label = '') {
    const key = `${src}->${dst}:${type}`;
    this.edges.set(key, { src, dst, type, label });
  }

  getAncestors(nodeId, visited = new Set()) {
    if (visited.has(nodeId)) return visited;
    visited.add(nodeId);
    for (let [, edge] of this.edges) {
      if (edge.dst === nodeId) this.getAncestors(edge.src, visited);
    }
    return visited;
  }

  getDescendants(nodeId, visited = new Set()) {
    if (visited.has(nodeId)) return visited;
    visited.add(nodeId);
    for (let [, edge] of this.edges) {
      if (edge.src === nodeId) this.getDescendants(edge.dst, visited);
    }
    return visited;
  }

  getEdgesInSubgraph(nodeSet) {
    const result = [];
    for (let [, edge] of this.edges) {
      if (nodeSet.has(edge.src) && nodeSet.has(edge.dst)) result.push(edge);
    }
    return result;
  }

  clear() {
    this.nodes.clear();
    this.edges.clear();
  }
}

class SVGRenderer {
  constructor(svgElementId) {
    this.svg = document.getElementById(svgElementId);
    if (!this.svg) return;
    this.graph = new ProvenanceGraph();
    this.selectedNode = null;
    this.highlightMode = null; // 'ancestors', 'descendants', or null
    this.highlightedSet = new Set();
    this.onNodeClick = null; // external callback
    this.nodeRadius = 30;
    this.setupDefs();
  }

  setupDefs() {
    const ns = 'http://www.w3.org/2000/svg';
    const defs = document.createElementNS(ns, 'defs');

    // Default arrowhead
    const marker = document.createElementNS(ns, 'marker');
    marker.setAttribute('id', `arrow-${this.svg.id}`);
    marker.setAttribute('markerWidth', '12');
    marker.setAttribute('markerHeight', '8');
    marker.setAttribute('refX', '11');
    marker.setAttribute('refY', '4');
    marker.setAttribute('orient', 'auto');
    const poly = document.createElementNS(ns, 'polygon');
    poly.setAttribute('points', '0 0, 12 4, 0 8');
    poly.setAttribute('fill', '#555');
    marker.appendChild(poly);
    defs.appendChild(marker);

    // Highlighted arrowhead
    const marker2 = document.createElementNS(ns, 'marker');
    marker2.setAttribute('id', `arrow-hl-${this.svg.id}`);
    marker2.setAttribute('markerWidth', '12');
    marker2.setAttribute('markerHeight', '8');
    marker2.setAttribute('refX', '11');
    marker2.setAttribute('refY', '4');
    marker2.setAttribute('orient', 'auto');
    const poly2 = document.createElementNS(ns, 'polygon');
    poly2.setAttribute('points', '0 0, 12 4, 0 8');
    poly2.setAttribute('fill', '#e07b39');
    marker2.appendChild(poly2);
    defs.appendChild(marker2);

    this.svg.appendChild(defs);
  }

  addNode(id, label, type, x, y) {
    this.graph.addNode(id, label, type, x, y);
    this.render();
  }

  addEdge(src, dst, type, label = '') {
    this.graph.addEdge(src, dst, type, label);
    this.render();
  }

  highlight(nodeId, mode) {
    this.selectedNode = nodeId;
    this.highlightMode = mode;
    if (mode === 'ancestors') {
      this.highlightedSet = this.graph.getAncestors(nodeId);
    } else if (mode === 'descendants') {
      this.highlightedSet = this.graph.getDescendants(nodeId);
    } else {
      this.highlightedSet = new Set([nodeId]);
    }
    this.render();
  }

  clearHighlight() {
    this.selectedNode = null;
    this.highlightMode = null;
    this.highlightedSet = new Set();
    this.render();
  }

  reset() {
    this.graph.clear();
    this.clearHighlight();
  }

  render() {
    const ns = 'http://www.w3.org/2000/svg';
    // Remove everything except defs
    while (this.svg.children.length > 1) {
      this.svg.removeChild(this.svg.lastChild);
    }

    const hasHighlight = this.highlightedSet.size > 0;

    // Draw edges
    for (let [, edge] of this.graph.edges) {
      const src = this.graph.nodes.get(edge.src);
      const dst = this.graph.nodes.get(edge.dst);
      if (!src || !dst) continue;

      const edgeHL = hasHighlight && this.highlightedSet.has(edge.src) && this.highlightedSet.has(edge.dst);
      const opacity = hasHighlight ? (edgeHL ? 1 : 0.12) : 1;
      const color = edgeHL ? '#e07b39' : '#555';
      const sw = edgeHL ? 2.5 : 1.5;

      // Shorten line to not overlap node shapes
      const dx = dst.x - src.x, dy = dst.y - src.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const ux = dx / dist, uy = dy / dist;
      const r = this.nodeRadius + 4;
      const x1 = src.x + ux * r, y1 = src.y + uy * r;
      const x2 = dst.x - ux * r, y2 = dst.y - uy * r;

      const line = document.createElementNS(ns, 'line');
      line.setAttribute('x1', x1); line.setAttribute('y1', y1);
      line.setAttribute('x2', x2); line.setAttribute('y2', y2);
      line.setAttribute('stroke', color);
      line.setAttribute('stroke-width', sw);
      line.setAttribute('opacity', opacity);
      line.setAttribute('marker-end', `url(#arrow-${edgeHL ? 'hl-' : ''}${this.svg.id})`);
      this.svg.appendChild(line);

      if (edge.label) {
        const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
        // Offset label perpendicular to the edge
        const px = -uy * 12, py = ux * 12;
        const lbl = document.createElementNS(ns, 'text');
        lbl.setAttribute('x', mx + px); lbl.setAttribute('y', my + py);
        lbl.setAttribute('text-anchor', 'middle');
        lbl.setAttribute('font-size', '11');
        lbl.setAttribute('font-weight', '600');
        lbl.setAttribute('fill', edgeHL ? '#c05a20' : '#666');
        lbl.setAttribute('opacity', opacity);
        lbl.textContent = edge.label;
        this.svg.appendChild(lbl);
      }
    }

    // Draw nodes
    for (let [id, node] of this.graph.nodes) {
      const hl = hasHighlight && this.highlightedSet.has(id);
      const opacity = hasHighlight ? (hl ? 1 : 0.15) : 1;
      const typeInfo = this.graph.nodeTypes[node.type] || { color: '#999', shape: 'circle' };

      const g = document.createElementNS(ns, 'g');
      g.style.cursor = 'pointer';
      g.setAttribute('opacity', opacity);

      // Shape
      const r = this.nodeRadius;
      let shape;
      if (typeInfo.shape === 'rect') {
        shape = document.createElementNS(ns, 'rect');
        shape.setAttribute('x', node.x - r); shape.setAttribute('y', node.y - r * 0.7);
        shape.setAttribute('width', r * 2); shape.setAttribute('height', r * 1.4);
        shape.setAttribute('rx', '4');
      } else if (typeInfo.shape === 'diamond') {
        shape = document.createElementNS(ns, 'polygon');
        shape.setAttribute('points',
          `${node.x},${node.y - r} ${node.x + r},${node.y} ${node.x},${node.y + r} ${node.x - r},${node.y}`);
      } else {
        shape = document.createElementNS(ns, 'circle');
        shape.setAttribute('cx', node.x); shape.setAttribute('cy', node.y);
        shape.setAttribute('r', r);
      }
      shape.setAttribute('fill', typeInfo.color);
      shape.setAttribute('stroke', hl ? '#000' : '#444');
      shape.setAttribute('stroke-width', hl ? '3' : '1.5');
      g.appendChild(shape);

      // Label (two lines if needed)
      const label = node.label;
      const maxLen = 12;
      const lines = label.length > maxLen
        ? [label.substring(0, maxLen), label.substring(maxLen, maxLen * 2)]
        : [label];

      lines.forEach((line, i) => {
        const t = document.createElementNS(ns, 'text');
        t.setAttribute('x', node.x);
        t.setAttribute('y', node.y + (i - (lines.length - 1) / 2) * 13);
        t.setAttribute('text-anchor', 'middle');
        t.setAttribute('dy', '0.35em');
        t.setAttribute('font-size', '11');
        t.setAttribute('font-weight', '600');
        t.setAttribute('fill', '#fff');
        t.setAttribute('pointer-events', 'none');
        t.textContent = line;
        g.appendChild(t);
      });

      // Type badge beneath node
      const badge = document.createElementNS(ns, 'text');
      badge.setAttribute('x', node.x);
      badge.setAttribute('y', node.y + r + 14);
      badge.setAttribute('text-anchor', 'middle');
      badge.setAttribute('font-size', '10');
      badge.setAttribute('fill', '#888');
      badge.setAttribute('pointer-events', 'none');
      badge.textContent = node.type;
      g.appendChild(badge);

      g.addEventListener('click', () => {
        if (this.onNodeClick) {
          this.onNodeClick(id, node);
          return;
        }
        if (this.selectedNode === id) {
          this.clearHighlight();
        } else {
          this.highlight(id, this.highlightMode || 'ancestors');
        }
      });

      this.svg.appendChild(g);
    }
  }
}

// Step-by-step scenario builder
class ScenarioBuilder {
  constructor(renderer) {
    this.renderer = renderer;
    this.steps = []; // each step = { actions: [...], explanation: '' }
    this.currentStep = -1;
  }

  addStep(explanation, actions) {
    this.steps.push({ explanation, actions });
  }

  next() {
    if (this.currentStep >= this.steps.length - 1) return false;
    this.currentStep++;
    const step = this.steps[this.currentStep];
    for (const action of step.actions) {
      if (action.type === 'node') {
        this.renderer.addNode(action.id, action.label, action.nodeType, action.x, action.y);
      } else if (action.type === 'edge') {
        this.renderer.addEdge(action.src, action.dst, action.edgeType, action.label);
      }
    }
    return true;
  }

  getExplanation() {
    if (this.currentStep < 0) return null;
    return this.steps[this.currentStep].explanation;
  }

  reset() {
    this.currentStep = -1;
    this.renderer.reset();
  }

  isComplete() {
    return this.currentStep >= this.steps.length - 1;
  }

  totalSteps() {
    return this.steps.length;
  }

  currentStepNum() {
    return this.currentStep + 1;
  }
}

// Dependency explosion demo — builds a graph showing fan-out problem
class ExplosionDemo {
  constructor(renderer) {
    this.renderer = renderer;
    this.phase = 0;
  }

  buildPhase(n) {
    this.renderer.reset();
    this.phase = n;

    // Apache process at center
    this.renderer.addNode('apache', 'httpd', 'process', 400, 50);

    // Shared libraries
    if (n >= 1) {
      this.renderer.addNode('libc', 'libc.so', 'file', 200, 140);
      this.renderer.addNode('libssl', 'libssl.so', 'file', 600, 140);
      this.renderer.addEdge('apache', 'libc', 'READ', 'READ');
      this.renderer.addEdge('apache', 'libssl', 'READ', 'READ');
    }

    // Config + log files
    if (n >= 2) {
      this.renderer.addNode('conf', 'httpd.conf', 'file', 100, 230);
      this.renderer.addNode('log', 'access.log', 'file', 700, 230);
      this.renderer.addEdge('apache', 'conf', 'READ', 'READ');
      this.renderer.addEdge('apache', 'log', 'WRITE', 'WRITE');
    }

    // Client requests (fan-in)
    if (n >= 3) {
      const clients = ['client_A', 'client_B', 'client_C', 'client_D'];
      clients.forEach((c, i) => {
        const x = 120 + i * 180;
        this.renderer.addNode(c, c.replace('_', ' '), 'socket', x, 340);
        this.renderer.addEdge(c, 'apache', 'SEND', 'REQ');
      });
    }

    // Served files (fan-out) — each request touches same files
    if (n >= 4) {
      const pages = ['index.html', 'style.css', 'app.js', 'logo.png'];
      pages.forEach((p, i) => {
        const x = 120 + i * 180;
        this.renderer.addNode(p, p, 'file', x, 440);
        this.renderer.addEdge('apache', p, 'READ', 'READ');
      });
    }
  }
}

// Interactive graph builder — lets students add nodes/edges
class GraphBuilder {
  constructor(renderer, statusEl) {
    this.renderer = renderer;
    this.statusEl = statusEl;
    this.nextId = 1;
    this.mode = 'add-node'; // 'add-node' or 'add-edge'
    this.edgeSrc = null;
    this.selectedType = 'process';
    this.selectedEdgeType = 'READ';

    this.renderer.onNodeClick = (id, node) => {
      if (this.mode === 'add-edge') {
        if (!this.edgeSrc) {
          this.edgeSrc = id;
          this.setStatus(`Source: <strong>${node.label}</strong>. Now click the destination node.`);
        } else {
          this.renderer.addEdge(this.edgeSrc, id, this.selectedEdgeType, this.selectedEdgeType);
          this.setStatus(`Edge added: ${this.edgeSrc} → ${id} (${this.selectedEdgeType})`);
          this.edgeSrc = null;
        }
      }
    };
  }

  setStatus(html) {
    if (this.statusEl) this.statusEl.innerHTML = html;
  }

  addNodeAt(label) {
    const id = `n${this.nextId++}`;
    // Place nodes in a grid-like pattern
    const col = (this.nextId - 1) % 4;
    const row = Math.floor((this.nextId - 1) / 4);
    const x = 120 + col * 170;
    const y = 80 + row * 120;
    this.renderer.addNode(id, label || `Node ${this.nextId - 1}`, this.selectedType, x, y);
    this.setStatus(`Added <strong>${label || 'Node ' + (this.nextId - 1)}</strong> (${this.selectedType})`);
  }

  startEdgeMode() {
    this.mode = 'add-edge';
    this.edgeSrc = null;
    this.setStatus('Click the <strong>source</strong> node for the edge.');
  }

  startNodeMode() {
    this.mode = 'add-node';
    this.edgeSrc = null;
    this.setStatus('Enter a label and click "Add Node".');
  }

  clear() {
    this.renderer.reset();
    this.nextId = 1;
    this.edgeSrc = null;
    this.setStatus('Graph cleared.');
  }
}
