// Provenance Graph Engine - Vanilla JS SVG Renderer

class ProvenanceGraph {
  constructor() {
    this.nodes = new Map(); // id -> {id, label, type, x, y}
    this.edges = new Map(); // "src->dst" -> {src, dst, type, label}
    this.nodeTypes = {
      process: { color: '#e07b39', icon: '◉' },
      file: { color: '#3a7fc1', icon: '▭' },
      socket: { color: '#2e9e5b', icon: '◇' },
      registry: { color: '#7c4db8', icon: '⬡' }
    };
  }

  addNode(id, label, type, x, y) {
    this.nodes.set(id, { id, label, type, x, y });
  }

  addEdge(src, dst, type, label = '') {
    const key = `${src}->${dst}`;
    this.edges.set(key, { src, dst, type, label });
  }

  getNodeAncestors(nodeId, visited = new Set()) {
    if (visited.has(nodeId)) return [];
    visited.add(nodeId);
    let ancestors = [];

    for (let [key, edge] of this.edges) {
      if (edge.dst === nodeId) {
        ancestors.push(edge.src);
        ancestors.push(...this.getNodeAncestors(edge.src, visited));
      }
    }
    return ancestors;
  }

  getNodeDescendants(nodeId, visited = new Set()) {
    if (visited.has(nodeId)) return [];
    visited.add(nodeId);
    let descendants = [];

    for (let [key, edge] of this.edges) {
      if (edge.src === nodeId) {
        descendants.push(edge.dst);
        descendants.push(...this.getNodeDescendants(edge.dst, visited));
      }
    }
    return descendants;
  }

  clear() {
    this.nodes.clear();
    this.edges.clear();
  }
}

class SVGRenderer {
  constructor(svgElementId) {
    this.svg = document.getElementById(svgElementId);
    this.graph = new ProvenanceGraph();
    this.selectedNode = null;
    this.highlightMode = null; // 'ancestors' or 'descendants'

    // Set up marker for arrowheads
    this.setupMarkers();
  }

  setupMarkers() {
    const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
    const marker = document.createElementNS('http://www.w3.org/2000/svg', 'marker');
    marker.setAttribute('id', 'arrowhead');
    marker.setAttribute('markerWidth', '10');
    marker.setAttribute('markerHeight', '10');
    marker.setAttribute('refX', '9');
    marker.setAttribute('refY', '3');
    marker.setAttribute('orient', 'auto');

    const polygon = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
    polygon.setAttribute('points', '0 0, 10 3, 0 6');
    polygon.setAttribute('fill', '#666');

    marker.appendChild(polygon);
    defs.appendChild(marker);
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

  highlightAncestors(nodeId) {
    this.selectedNode = nodeId;
    this.highlightMode = 'ancestors';
    this.render();
  }

  highlightDescendants(nodeId) {
    this.selectedNode = nodeId;
    this.highlightMode = 'descendants';
    this.render();
  }

  clearHighlight() {
    this.selectedNode = null;
    this.highlightMode = null;
    this.render();
  }

  reset() {
    this.graph.clear();
    this.selectedNode = null;
    this.highlightMode = null;
    this.render();
  }

  render() {
    // Clear previous content (except defs)
    while (this.svg.children.length > 1) {
      this.svg.removeChild(this.svg.children[1]);
    }

    // Compute highlighted nodes
    let highlightedNodes = new Set();
    if (this.selectedNode) {
      highlightedNodes.add(this.selectedNode);
      if (this.highlightMode === 'ancestors') {
        this.graph.getNodeAncestors(this.selectedNode).forEach(n => highlightedNodes.add(n));
      } else if (this.highlightMode === 'descendants') {
        this.graph.getNodeDescendants(this.selectedNode).forEach(n => highlightedNodes.add(n));
      }
    }

    // Draw edges first (so they appear under nodes)
    for (let [key, edge] of this.graph.edges) {
      const srcNode = this.graph.nodes.get(edge.src);
      const dstNode = this.graph.nodes.get(edge.dst);

      if (srcNode && dstNode) {
        this.drawEdge(srcNode, dstNode, edge, highlightedNodes);
      }
    }

    // Draw nodes
    for (let [id, node] of this.graph.nodes) {
      const isHighlighted = highlightedNodes.has(id);
      this.drawNode(node, isHighlighted);
    }
  }

  drawNode(node, isHighlighted) {
    const nodeGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    nodeGroup.setAttribute('class', 'node');
    nodeGroup.setAttribute('data-id', node.id);

    const typeInfo = this.graph.nodeTypes[node.type] || { color: '#999', icon: '●' };
    const strokeWidth = isHighlighted ? '3' : '2';
    const opacity = (this.selectedNode && !isHighlighted) ? '0.2' : '1';

    // Draw circle background
    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', node.x);
    circle.setAttribute('cy', node.y);
    circle.setAttribute('r', '35');
    circle.setAttribute('fill', typeInfo.color);
    circle.setAttribute('stroke', '#000');
    circle.setAttribute('stroke-width', strokeWidth);
    circle.setAttribute('opacity', opacity);
    nodeGroup.appendChild(circle);

    // Draw label
    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('x', node.x);
    text.setAttribute('y', node.y);
    text.setAttribute('text-anchor', 'middle');
    text.setAttribute('dy', '0.3em');
    text.setAttribute('font-size', '12');
    text.setAttribute('font-weight', 'bold');
    text.setAttribute('fill', '#fff');
    text.setAttribute('pointer-events', 'none');
    text.textContent = node.label.length > 8 ? node.label.substring(0, 8) : node.label;
    nodeGroup.appendChild(text);

    // Add click handler
    nodeGroup.addEventListener('click', () => {
      if (this.selectedNode === node.id && this.highlightMode) {
        this.clearHighlight();
      } else {
        this.highlightAncestors(node.id);
      }
    });
    nodeGroup.style.cursor = 'pointer';

    this.svg.appendChild(nodeGroup);
  }

  drawEdge(srcNode, dstNode, edge, highlightedNodes) {
    const isHighlighted = highlightedNodes.has(srcNode.id) || highlightedNodes.has(dstNode.id);
    const opacity = (this.selectedNode && !isHighlighted) ? '0.15' : '1';
    const strokeWidth = isHighlighted ? '2.5' : '1.5';

    // Draw line
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    line.setAttribute('x1', srcNode.x);
    line.setAttribute('y1', srcNode.y);
    line.setAttribute('x2', dstNode.x);
    line.setAttribute('y2', dstNode.y);
    line.setAttribute('stroke', '#666');
    line.setAttribute('stroke-width', strokeWidth);
    line.setAttribute('marker-end', 'url(#arrowhead)');
    line.setAttribute('opacity', opacity);
    this.svg.appendChild(line);

    // Draw label midpoint
    if (edge.label) {
      const midX = (srcNode.x + dstNode.x) / 2;
      const midY = (srcNode.y + dstNode.y) / 2;

      const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      text.setAttribute('x', midX);
      text.setAttribute('y', midY - 5);
      text.setAttribute('text-anchor', 'middle');
      text.setAttribute('font-size', '11');
      text.setAttribute('fill', '#333');
      text.setAttribute('opacity', opacity);
      text.textContent = edge.label;
      this.svg.appendChild(text);
    }
  }
}

// Scenario builder for step-by-step demo
class ScenarioBuilder {
  constructor(renderer) {
    this.renderer = renderer;
    this.steps = [];
    this.currentStep = 0;
  }

  addStep(action, params) {
    this.steps.push({ action, params });
  }

  nextStep() {
    if (this.currentStep < this.steps.length) {
      const step = this.steps[this.currentStep];

      if (step.action === 'addNode') {
        const { id, label, type, x, y } = step.params;
        this.renderer.addNode(id, label, type, x, y);
      } else if (step.action === 'addEdge') {
        const { src, dst, type, label } = step.params;
        this.renderer.addEdge(src, dst, type, label);
      }

      this.currentStep++;
      return this.currentStep <= this.steps.length;
    }
    return false;
  }

  reset() {
    this.currentStep = 0;
    this.renderer.reset();
  }

  isComplete() {
    return this.currentStep >= this.steps.length;
  }
}
