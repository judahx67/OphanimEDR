import { useState } from "react";

/* ─── PALETTE ───────────────────────────────────────────────────────────── */
const C = {
  blue:   "#60a5fa",
  teal:   "#2dd4bf",
  purple: "#a78bfa",
  orange: "#fb923c",
  green:  "#34d399",
  red:    "#f87171",
  amber:  "#fbbf24",
  pink:   "#f472b6",
};

/* ─── SECTIONS ──────────────────────────────────────────────────────────── */
const SECTIONS = [
  { id: "positioning",  label: "Thesis positioning",     group: "FOUNDATION",  color: C.blue   },
  { id: "pipeline",     label: "Full pipeline",          group: "FOUNDATION",  color: C.teal   },
  { id: "projection",   label: "NodeTypeProjection",     group: "ENCODER",     color: C.purple },
  { id: "gat",          label: "GAT layer (1-layer)",    group: "ENCODER",     color: C.purple },
  { id: "gru",          label: "GRU cell",               group: "ENCODER",     color: C.purple },
  { id: "decoder",      label: "EdgeDecoder + score",    group: "ENCODER",     color: C.purple },
  { id: "streaming",    label: "Per-event streaming",    group: "KEY CHANGES", color: C.orange },
  { id: "drift",        label: "Drift adaptation",       group: "KEY CHANGES", color: C.orange },
  { id: "scoring",      label: "Scoring improvements",   group: "KEY CHANGES", color: C.green  },
  { id: "memory",       label: "Bounded memory",         group: "KEY CHANGES", color: C.amber  },
  { id: "roadmap",      label: "12-week roadmap",        group: "PLANNING",    color: C.pink   },
];

/* ─── CONTENT ───────────────────────────────────────────────────────────── */
const CONTENT = {

  positioning: {
    color: C.blue,
    title: "Where Ophanim-EDR sits in the literature",
    tldr: "No published system achieves both edge-level detection AND online drift adaptation simultaneously. That gap is the thesis.",
    analogy: {
      icon: "🗺️",
      title: "A map of the field — and the empty square",
      body: `Think of the research landscape as a 2×2 grid with two axes:

Axis 1 — Detection granularity:
  Window-based  ←────────────────→  Edge-level (per-event)

Axis 2 — Model adaptability:
  Static (fixed after training)  ←──→  Online (adapts to new patterns)

Where each system lives:
  KAIROS   → Window-based   + Static      ← prior art
  ORCHID   → Edge-level     + Static      ← faster but still static  
  METANOIA → Window-based   + Online      ← adapts but still windowed
  CAPTAIN  → Edge-level     + Adaptive    ← but rule-based, not neural

The (Edge-level + Online + Neural) cell is EMPTY.
That is exactly where Ophanim-EDR sits.`,
    },
    faqs: [
      {
        q: "What does 'window-based' vs 'edge-level' mean in practice?",
        a: "KAIROS buffers 15 minutes of events, then asks: 'was this window suspicious?' An attack that begins at minute 1 cannot trigger an alert until minute 15 closes — a worst-case 15-minute detection delay. Edge-level detection asks: 'is THIS specific event suspicious?' — the moment it arrives. Worst-case detection delay becomes single-digit seconds.",
      },
      {
        q: "What is 'concept drift' and why does it matter?",
        a: "Your model trains on DARPA TC E3 benign data from a specific time period. Six months later, the Windows version updates, new software is installed, user habits change. The definition of 'normal' shifts. A static model trained on old data will start raising false alarms for the new normal — that is concept drift. Systems like KAIROS explicitly exclude this from their threat model. Ophanim-EDR addresses it.",
      },
      {
        q: "Why cite KAIROS, ORCHID, METANOIA, and CAPTAIN in the thesis?",
        a: "Each fills one quadrant of the grid. KAIROS is the strongest academic baseline (IEEE S&P 2024, 100% recall). ORCHID shows edge-level is feasible (arXiv 2408.13347). METANOIA shows online adaptation is feasible (arXiv 2501.00438). CAPTAIN shows adaptive edge-level detection is useful (NDSS 2025). Your system is the first neural approach combining all three properties.",
      },
      {
        q: "What is the correct way to state the latency contribution?",
        a: "NOT: 'we reduce KAIROS's 11.6s to under 1s' — that is wrong. KAIROS already handles under 1s for small windows. CORRECT: 'KAIROS's time-window architecture introduces detection latency of up to one full window duration (15 minutes) regardless of computational speed. Ophanim-EDR's edge-level scoring eliminates this architectural latency, detecting anomalies at the moment of event arrival.' The contribution is architectural, not computational.",
      },
    ],
    sources: [
      { label: "KAIROS — IEEE S&P 2024", ref: "arXiv:2308.05034", note: "Baseline. Time-window detection, static model, 100% recall." },
      { label: "ORCHID — arXiv 2024", ref: "arXiv:2408.13347", note: "Edge-level streaming via RNN. 0.002s/event. Static." },
      { label: "METANOIA — arXiv 2024", ref: "arXiv:2501.00438", note: "Lifelong learning for provenance IDS. Window-based." },
      { label: "CAPTAIN — NDSS 2025", ref: "arXiv:2404.14720", note: "Adaptive rule-based edge detection. <10% CPU, 93% FP reduction." },
    ],
  },

  pipeline: {
    color: C.teal,
    title: "The full modified pipeline",
    tldr: "Six stages, each building on the previous. The first four form the encoder-decoder. The last two are new contributions.",
    analogy: {
      icon: "🏭",
      title: "Like an assembly line",
      body: `Think of a car assembly line. Raw metal arrives at one end;
a finished, inspected car leaves the other.
Each station does one specific job and passes the result forward.

Your pipeline works the same way:

  Raw event (XML)
    ↓ Station 1 — NodeTypeProjection
      Converts diverse node types into a common language (64 numbers each)
    ↓ Station 2 — GAT Layer  
      Each node "looks at" its neighbours and updates its own representation
    ↓ Station 3 — GRU Cell
      Remembers what this node was doing in the past, updates its memory
    ↓ Station 4 — EdgeDecoder
      Given two updated nodes, predicts: should this edge exist? What type?
    ↓ Station 5 — Anomaly Score
      Compares prediction to reality: high mismatch = suspicious
    ↓ Station 6 — Drift Adaptation
      Updates the model's notion of "normal" without forgetting the past

Stations 1–4 are the core encoder-decoder (already in encoder.py).
Stations 5–6 are the thesis contribution.`,
    },
    pipeline_steps: [
      { num: "01", name: "NodeTypeProjection", dim: "4–12 → 64", color: C.purple, desc: "Standardise heterogeneous node features into one embedding space." },
      { num: "02", name: "1-layer GAT",        dim: "64 → 64",  color: C.purple, desc: "Aggregate neighbour context via learned attention weights." },
      { num: "03", name: "GRU Cell",           dim: "64h-state", color: C.purple, desc: "Encode temporal history of each node as a compact hidden state." },
      { num: "04", name: "EdgeDecoder",        dim: "128 → 2",  color: C.teal,   desc: "Predict edge existence and type from source + target embeddings." },
      { num: "05", name: "Anomaly Score",      dim: "scalar",   color: C.orange, desc: "IDF-weighted reconstruction error → per-event threat signal." },
      { num: "06", name: "Drift Adaptation",   dim: "online",   color: C.green,  desc: "EMA + reservoir replay + KD regularisation → continual learning." },
    ],
    faqs: [
      {
        q: "Why is this called an 'encoder-decoder' architecture?",
        a: "The Encoder (Projection + GAT + GRU) takes a node and all its context and compresses everything into a small, dense vector (64 numbers). The Decoder (EdgeDecoder) takes two of these dense vectors and tries to reconstruct the relationship between those nodes. If reconstruction fails — the model couldn't predict what kind of edge this was — something unusual is happening. This 'compression → reconstruction' pattern is the core principle of all self-supervised anomaly detection.",
      },
      {
        q: "What changed from the original architecture in encoder.py?",
        a: "Three changes: (1) GAT reduced from 2 layers to 1 layer — 10× speed improvement with minimal accuracy loss. (2) Hidden dimensions reduced from 128 to 64 — halves memory per node. (3) Anomaly score is now IDF-weighted and per-edge rather than aggregated over windows. The fundamental encoder-decoder structure is unchanged.",
      },
      {
        q: "Why does the architecture output per-edge scores rather than a single graph-level score?",
        a: "A single graph-level score (KAIROS's approach) answers: 'was this 15-minute session suspicious?' A per-edge score answers: 'was THIS specific process write to THIS specific file suspicious?' The second is far more useful operationally — analysts can immediately see which event triggered the alert, rather than inspecting an entire 15-minute window.",
      },
    ],
    sources: [
      { label: "KAIROS encoder design", ref: "arXiv:2308.05034 §3", note: "TGN + UniMP GNN + MLP decoder. Our architecture is analogous but uses GAT instead of UniMP." },
      { label: "MAGIC masked autoencoder", ref: "arXiv:2310.09831", note: "Alternative self-supervised approach — BERT-style masking instead of edge reconstruction." },
    ],
  },

  projection: {
    color: C.purple,
    title: "NodeTypeProjection — the universal translator",
    tldr: "Different node types (Process, File, Network, Registry) have different numbers of features. This layer converts them all into the same 64-number format so the GAT can process them uniformly.",
    analogy: {
      icon: "🔌",
      title: "Like a power adapter",
      body: `You're travelling and you have:
  • A US plug (2 flat pins)
  • A UK plug (3 square pins)  
  • A European plug (2 round pins)

All of them carry electricity — but you can't plug them into the same socket without an adapter.

NodeTypeProjection is the adapter. Each node type (Process, File, Network socket, Registry key) carries information — but in a different shape:
  • Process node   → 8 features (PID, parent PID, path hash, privilege level…)
  • File node      → 4 features (path hash, extension, size, permissions)
  • Socket node    → 6 features (IP, port, protocol, bytes sent…)
  • Registry node  → 5 features (key path hash, value type, write count…)

A separate small linear layer per type converts each into 64 numbers.
After projection, every node speaks the same language: a 64-number vector.
Now the GAT can process all node types in a single unified pass.`,
    },
    faqs: [
      {
        q: "What is a 'linear layer' (also called 'fully connected layer')?",
        a: "A linear layer performs one operation: output = W × input + b. W is a matrix of learnable weights, b is a bias vector. For NodeTypeProjection, if a Process node has 8 input features, W is a 64×8 matrix (64 output dimensions × 8 input dimensions). The model learns W and b during training so that the 64 output numbers are the most useful representation for downstream processing.",
      },
      {
        q: "Why 64 dimensions specifically?",
        a: "64 was chosen based on ORCHID's empirical finding that provenance graph embeddings show diminishing returns beyond 64 dimensions. KAIROS uses larger embeddings but pays a memory cost: their full node embedding table on E3-THEIA is several GB. At 64 dimensions, your 690K nodes in E3-THEIA require only 177 MB — comfortably within T4 VRAM even with full graph loading.",
      },
      {
        q: "Why not just pad all node types with zeros to the same size?",
        a: "Zero-padding wastes capacity and introduces noise. If Process nodes have 8 meaningful features and we zero-pad to 12 to match Socket nodes, the 4 extra zeros carry no information but the GAT still processes them. A dedicated linear projection per type is computationally cheap (5 extra small matrices) and produces strictly better representations.",
      },
      {
        q: "What is the CDM schema and why does it matter here?",
        a: "DARPA CDM (Common Data Model) is a standardised format for provenance data used in the DARPA TC datasets (E3, E5, OpTC). It defines exactly which node types exist and what fields they have. Because Ophanim-EDR uses CDM-aligned schema, the NodeTypeProjection layers can be defined precisely before training, and the system is compatible with all three benchmark datasets.",
      },
    ],
    code: `# Each node type gets its own projection layer
# Defined once at model init; weights learned during pretraining

class NodeTypeProjection(nn.Module):
    def __init__(self, type_feature_dims: dict, out_dim=64):
        super().__init__()
        # One linear layer per node type
        # type_feature_dims = {
        #   'process': 8,  'file': 4,
        #   'socket': 6,   'registry': 5, 'memory': 4, 'other': 3
        # }
        self.projectors = nn.ModuleDict({
            node_type: nn.Linear(in_dim, out_dim)
            for node_type, in_dim in type_feature_dims.items()
        })

    def forward(self, x: torch.Tensor, node_types: list[str]) -> torch.Tensor:
        # x: [N_nodes, max_feature_dim]  (padded)
        # We apply the correct projector per node type
        out = torch.zeros(x.size(0), 64, device=x.device)
        for ntype, proj in self.projectors.items():
            mask = [i for i, t in enumerate(node_types) if t == ntype]
            if mask:
                # slice only the relevant features for this type
                in_dim = proj.in_features
                out[mask] = proj(x[mask, :in_dim])
        return out  # shape: [N_nodes, 64]`,
    sources: [
      { label: "KAIROS node feature design", ref: "arXiv:2308.05034 §3.2", note: "Per-type feature extraction with heterogeneous feature vectors." },
      { label: "DARPA CDM schema", ref: "github.com/darpa-i2o/Transparent-Computing", note: "Defines the 6 node types and their CDM fields." },
    ],
  },

  gat: {
    color: C.purple,
    title: "Graph Attention Network — 1 layer, 4 heads, 64-dim",
    tldr: "Each node updates its representation by looking at its k=10 most recent neighbours, weighted by how relevant each neighbour is. The 'attention' mechanism learns which neighbours matter most.",
    analogy: {
      icon: "👁️",
      title: "Like a detective interviewing witnesses — but some witnesses are more reliable",
      body: `A detective is trying to understand a suspect (a process node).
She interviews 10 witnesses (neighbour nodes):
  • The process's parent (very relevant — spawned it)
  • Files it recently read (relevant)
  • Network connections it made (relevant)
  • Shared libraries it loaded (less relevant for this case)

A naive system would give every witness equal weight.
The GAT learns to assign importance: "the parent process matters 0.4,
the network socket matters 0.35, the library matters 0.05..."

These importance scores are called 'attention weights'.
They are not hardcoded — they are LEARNED from data.

4 Attention Heads = 4 detectives, each with a different specialty:
  Head 1 specialises in privilege flow (who gave elevated access to whom)
  Head 2 specialises in path legitimacy (does this file access look normal?)
  Head 3 specialises in communication patterns (network behaviour)  
  Head 4 specialises in spawn relationships (who created whom)

Their 4 independent verdicts (each 16 numbers) are concatenated into
one final 64-number representation for each node.`,
    },
    faqs: [
      {
        q: "What is a 'graph' in this context?",
        a: "A provenance graph has nodes (processes, files, sockets, registry keys) and edges (process spawned process, process read file, process connected to socket). Each edge is one event from Sysmon. The GAT's job is to process this graph structure so that each node's representation reflects not just its own features but also the context of everything it has interacted with.",
      },
      {
        q: "Why reduce from 2 layers to 1?",
        a: "Each GAT layer expands the 'receptive field' — the set of nodes a given node 'sees'. With k=10 neighbours and 2 layers, a node sees up to 10² = 100 nodes. That means sampling 100 nodes per event, plus running attention over 100 pairs — roughly 10× more computation than a 1-layer GAT. Since 97% of nodes in E3-THEIA have ≤ 20 total neighbours, a 1-hop (1-layer) neighbourhood already captures nearly all available context, making the second layer mostly redundant noise at significant cost.",
      },
      {
        q: "What is k=10 'local neighbourhood sampling'?",
        a: "Instead of passing every edge in the entire graph through the GAT (which grows unboundedly over time), we sample only the k=10 most recent temporal neighbours of each node. This bounds computation to O(k) per node regardless of graph size. In PyG, this is implemented with NeighborLoader(seed_nodes=[src, dst], num_neighbors=[10]).",
      },
      {
        q: "What are 'attention weights' mathematically?",
        a: "For two nodes i (target) and j (neighbour), the attention weight α_ij = softmax_j( LeakyReLU( a^T [W·h_i ‖ W·h_j] ) ). In plain English: project both node embeddings with a learned matrix W, concatenate them, pass through a small learned vector a to get a scalar, apply LeakyReLU for non-linearity, then normalise across all neighbours with softmax so weights sum to 1. The model learns W and a so that high scores go to genuinely informative neighbours.",
      },
      {
        q: "Why keep GAT instead of switching to ORCHID's simpler GRU-only approach?",
        a: "ORCHID achieves 0.002s/event by processing each edge as a simple GRU update with no neighbour awareness — effectively a dictionary of per-node sequences. This makes it blind to structural anomalies: a process touching 50 unusual files simultaneously looks identical to 50 separate single-file accesses, since no neighbourhood aggregation occurs. Your 1-layer GAT with k=10 catches this fan-out pattern. The interpretability argument also matters for a thesis: GAT attention weights can be visualised to show WHICH neighbours triggered the anomaly — something ORCHID fundamentally cannot provide.",
      },
    ],
    code: `from torch_geometric.nn import GATConv
import torch.nn as nn, torch

class TemporalGATEncoder(nn.Module):
    def __init__(self, in_dim=64, heads=4, head_dim=16):
        super().__init__()
        out_dim = heads * head_dim  # 4 × 16 = 64
        
        # Single GAT layer (changed from 2-layer original)
        self.gat = GATConv(
            in_channels=in_dim,
            out_channels=head_dim,  # per-head output
            heads=heads,            # 4 independent attention mechanisms
            concat=True,            # concatenate head outputs → 64-dim
            dropout=0.1,            # regularisation
        )
        self.norm = nn.LayerNorm(out_dim)
        self.act  = nn.ELU()

    def forward(self, x, edge_index):
        # x:          [N, 64]  — projected node features
        # edge_index: [2, E]   — (src, dst) pairs for k=10 neighbours
        
        h = self.gat(x, edge_index)   # [N, 64]
        h = self.norm(h)              # stabilise training
        h = self.act(h)               # non-linearity
        return h                      # [N, 64]

# How to get local neighbourhood (k=10) instead of full graph:
# from torch_geometric.loader import NeighborLoader
# loader = NeighborLoader(data, num_neighbors=[10],
#                         input_nodes=torch.tensor([src_id, dst_id]))`,
    sources: [
      { label: "GAT original paper", ref: "Veličković et al., ICLR 2018 (arXiv:1710.10903)", note: "Defines the attention mechanism used in GATConv." },
      { label: "GAT vs GCN for security", ref: "docs/07-design-justification.md §GAT", note: "~98.3% vs ~96.25% accuracy; attention provides interpretable per-edge importance." },
      { label: "1-hop sufficiency on E3-THEIA", ref: "ORCHID arXiv:2408.13347 §5.2", note: "97% of E3-THEIA nodes have neighbourhood size ≤ 20." },
    ],
  },

  gru: {
    color: C.purple,
    title: "GRU Cell — the model's short-term memory",
    tldr: "After the GAT updates a node's embedding with spatial context, the GRU updates it with temporal context — what has this node been doing over time?",
    analogy: {
      icon: "📔",
      title: "Like a running notebook for each process",
      body: `Imagine each node (each process, each file) has a personal notebook.
Every time an event involves that node, the notebook is updated.

The notebook has limited space — it holds exactly 64 numbers.
When new information arrives, the GRU decides:
  • What from the old notebook to KEEP (forget gate)
  • What new information to ADD (update gate)
  • What the new notebook summary should be (new hidden state)

Example — a process that starts innocent then turns malicious:
  t=0:  process spawned by explorer.exe → notebook: "normal process"
  t=1:  process reads config.ini → notebook: "reading config, still normal"
  t=2:  process opens network socket → notebook: "unusual — added to memory"
  t=3:  process downloads file → notebook: "very unusual — high alert"
  t=4:  process writes to startup registry → notebook: "SUSPICIOUS SEQUENCE"

The GAT at time t=4 only sees the current neighbourhood snapshot.
The GRU's notebook captures that THIS process went through a concerning evolution.
Together they catch attacks that unfold over time (the majority of real APTs).`,
    },
    faqs: [
      {
        q: "What is a 'hidden state'?",
        a: "The hidden state is the 64 numbers in the notebook. It is the GRU's compressed memory of everything that has happened to this node so far. Formally: h_t = GRU(h_{t-1}, x_t), where h_{t-1} is the old hidden state, x_t is the new event's embedding from the GAT, and h_t is the updated hidden state. Every time an edge touches a node, its hidden state is updated.",
      },
      {
        q: "Why GRU and not LSTM?",
        a: "LSTM has 4 gate operations per update (input, forget, output, cell). GRU has 2 (reset, update). For 690K nodes in E3-THEIA, this means ~25% fewer parameters and ~25% fewer operations per update. KAIROS explicitly validated that GRU is sufficient for provenance sequences — the shorter sequences in APT attack chains don't require LSTM's longer memory capacity. This is documented in docs/07-design-justification.md.",
      },
      {
        q: "What is the difference between GAT and GRU in terms of what they capture?",
        a: "GAT captures SPATIAL context: at time t, what does the current neighbourhood look like? GRU captures TEMPORAL context: across ALL times, how has this node's behaviour evolved? A purely spatial model (GAT alone) can't detect gradual compromise — each snapshot looks locally normal. A purely temporal model (GRU alone, like ORCHID) can't detect structural anomalies like unusual fan-out. Together they cover both attack patterns.",
      },
      {
        q: "Are GRU hidden states stored for all 690K nodes?",
        a: "Yes, and this is one of the main memory costs. 690K nodes × 64 dimensions × 4 bytes (float32) = 176 MB. This is the primary reason we chose 64-dim rather than 128-dim. The bounded-memory design section covers LRU eviction of inactive nodes to cap this at 512 MB for up to 2 million nodes.",
      },
    ],
    code: `class NodeGRUMemory(nn.Module):
    """Maintains a GRU hidden state per node, updated on each event."""
    def __init__(self, dim=64):
        super().__init__()
        self.gru_cell = nn.GRUCell(
            input_size=dim,   # GAT output embedding
            hidden_size=dim,  # hidden state same size
        )
        # In-memory store: node_id → hidden state tensor
        # (In production: backed by RocksDB or Redis)
        self.memory: dict[int, torch.Tensor] = {}

    def get_state(self, node_ids: list[int], device) -> torch.Tensor:
        """Retrieve current hidden states; initialise to zeros if unseen."""
        states = []
        for nid in node_ids:
            if nid in self.memory:
                states.append(self.memory[nid])
            else:
                states.append(torch.zeros(64, device=device))
        return torch.stack(states)  # [N, 64]

    def update(self, node_ids: list[int], gat_out: torch.Tensor):
        """Update hidden states with new GAT embeddings."""
        new_states = self.gru_cell(
            gat_out,                       # [N, 64] — new info
            self.get_state(node_ids,       # [N, 64] — old memory
                           gat_out.device)
        )
        for i, nid in enumerate(node_ids):
            self.memory[nid] = new_states[i].detach()
        return new_states  # [N, 64]`,
    sources: [
      { label: "GRU vs LSTM for sequences", ref: "Chung et al., 2014 (arXiv:1412.3555)", note: "Original empirical comparison showing GRU competitive with LSTM on most tasks." },
      { label: "KAIROS GRU choice", ref: "arXiv:2308.05034 §3.3", note: 'Explicitly uses GRU: "we use a GRU... as a simpler alternative to LSTM".' },
      { label: "TGN memory module", ref: "Rossi et al., 2020 (arXiv:2006.10637)", note: "Temporal Graph Networks — the theoretical framework for per-node memory in temporal graphs." },
    ],
  },

  decoder: {
    color: C.purple,
    title: "EdgeDecoder + Anomaly Score — the detection mechanism",
    tldr: "Given two node embeddings, predict whether their edge should exist and what type it should be. If reality doesn't match the prediction, the edge is anomalous. No attack labels needed.",
    analogy: {
      icon: "🔮",
      title: "Like a city planner who knows which roads should exist",
      body: `Imagine a city planner who has studied thousands of city maps.
She knows: "A hospital should connect to ambulance routes.
A school should connect to residential streets. 
A factory should NOT directly connect to a kindergarten."

After studying enough normal cities, she can look at two buildings and predict:
"Given what these buildings ARE, what kind of road SHOULD connect them?"

If reality shows a road that contradicts her prediction — something is wrong.

Your EdgeDecoder works exactly this way:
  Input:  embedding of process A (64 numbers) + embedding of file B (64 numbers)
  Task:   predict (1) does an edge exist? (2) what type is it?
  Output: probability distribution over 9 edge types + existence probability

If A is 'powershell.exe' and B is 'system32\drivers\...',
the model learned that powershell writing to driver directories is rare.
Low P(type=WRITE, src=powershell, dst=driver) → high anomaly score.

No one labelled "this is an attack". 
The model only learned what NORMAL looks like.`,
    },
    faqs: [
      {
        q: "What are the 9 edge types in the CDM schema?",
        a: "The DARPA CDM defines: WRITE, READ, EXECUTE, FORK/CLONE, CONNECT, SEND, RECEIVE, MMAP, and RENAME/LINK. Each maps to specific Sysmon event IDs. The decoder predicts which of these 9 types a new edge belongs to. If powershell.exe creates a FORK edge to an unknown binary, and the model predicted WRITE was overwhelmingly likely based on powershell's history, the FORK is anomalous.",
      },
      {
        q: "What is the anomaly score formula?",
        a: "score = −log P(edge_exists) + −log P(correct_type). Both terms are cross-entropy losses. −log P(exists) is high when the model thinks this edge is unlikely to exist at all. −log P(correct_type) is high when the model thinks the wrong edge type occurred. A high total score means: 'I did not expect this connection, and I especially did not expect THIS KIND of connection.'",
      },
      {
        q: "Why is this called 'self-supervised' learning?",
        a: "Supervised learning requires human labels: 'event 1234 is an attack'. Self-supervised learning creates labels from the data structure itself. Here, the task is: 'predict the edge type from the node embeddings'. The 'label' is the actual edge type that occurred — which we always have for free from the provenance logs. No security analyst needs to label anything. The model learns normality purely from unlabelled benign data.",
      },
      {
        q: "What loss functions are used during training?",
        a: "Binary Cross Entropy (BCE) for edge existence: Loss_exist = BCE(P(exists), actual_exists). Cross Entropy (CE) for edge type: Loss_type = CE(P(type), actual_type). Total training loss = Loss_exist + Loss_type. During training on benign data only, the model minimises this loss, which forces it to build accurate internal representations of normal system behaviour.",
      },
      {
        q: "What is the difference between your decoder and KAIROS's?",
        a: "KAIROS uses a 9-class MLP classifier as its decoder, predicting only edge type (not existence). Your decoder adds a second binary output for edge existence, providing an additional anomaly signal: edges that occur between nodes that 'should never interact' based on their embeddings will trigger the existence term even if the edge type prediction is accidentally correct.",
      },
    ],
    code: `class EdgeDecoder(nn.Module):
    """Predicts edge existence and type from src+dst embeddings."""
    def __init__(self, node_dim=64, n_edge_types=9):
        super().__init__()
        in_dim = node_dim * 2  # concatenate src and dst = 128-dim
        
        # Shared trunk
        self.trunk = nn.Sequential(
            nn.Linear(in_dim, 128),
            nn.ELU(),
            nn.Dropout(0.1),
            nn.Linear(128, 64),
            nn.ELU(),
        )
        # Two output heads
        self.head_exists = nn.Linear(64, 1)           # binary: does edge exist?
        self.head_type   = nn.Linear(64, n_edge_types) # 9-class: edge type

    def forward(self, z_src, z_dst):
        # z_src, z_dst: [N, 64]
        z_edge = torch.cat([z_src, z_dst], dim=-1)  # [N, 128]
        h      = self.trunk(z_edge)                  # [N, 64]
        
        p_exists = torch.sigmoid(self.head_exists(h)).squeeze(-1)  # [N]
        p_type   = F.softmax(self.head_type(h), dim=-1)            # [N, 9]
        return p_exists, p_type

def anomaly_score(p_exists, p_type, actual_exists, actual_type,
                  idf_weight=1.0):
    """
    Compute per-edge anomaly score.
    Higher = more anomalous.
    idf_weight: inverse doc frequency of (src_type, edge_type, dst_type)
    """
    bce = F.binary_cross_entropy(p_exists, actual_exists.float(), reduction='none')
    ce  = F.cross_entropy(
              p_type,
              actual_type,
              reduction='none'
          )
    raw_score = bce + ce               # both terms contribute
    return raw_score * idf_weight      # rare patterns amplified`,
    sources: [
      { label: "KAIROS EdgeDecoder design", ref: "arXiv:2308.05034 §3.4", note: "9-class MLP for edge type prediction. BCE reconstruction loss." },
      { label: "Self-supervised anomaly detection", ref: "MAGIC arXiv:2310.09831 §3", note: "Masked reconstruction as pretraining objective for provenance graphs." },
    ],
  },

  streaming: {
    color: C.orange,
    title: "Per-event streaming — eliminating window latency",
    tldr: "KAIROS buffers 15 minutes before deciding. Ophanim-EDR scores every edge the moment it arrives. Three specific code changes make this work.",
    analogy: {
      icon: "🚦",
      title: "The difference between a traffic camera and a speed trap",
      body: `A speed trap (KAIROS's window approach):
A camera photographs all cars over a 15-minute period.
At the end of 15 minutes, an officer reviews the footage
and decides if any car was speeding.
A car that sped through at minute 1 is not caught
until the review at minute 15.

A real-time radar gun (Ophanim's edge-level approach):
The moment a car passes, the radar fires and registers its speed.
If it's over the limit, the alert fires IMMEDIATELY.
There is no buffer, no batch, no 15-minute wait.

That is the entire difference:
  KAIROS: buffer → batch → decide (up to 15-min latency)
  Ophanim: arrive → score → decide (per-event, seconds latency)

The attack at minute 1 is caught at minute 1.`,
    },
    faqs: [
      {
        q: "Why does KAIROS use windows at all if per-event is faster?",
        a: "KAIROS's window approach is a deliberate design choice for APT detection specifically. APT attackers move slowly (KAIROS's E3-THEIA shows inter-step gaps of nearly an hour). Aggregating 15 minutes of events into a single graph provides richer context — more edges, more paths between suspicious events — which improves detection accuracy. The trade-off: it fundamentally cannot detect fast attacks. Ophanim's per-event approach sacrifices some context richness in exchange for zero window-boundary latency.",
      },
      {
        q: "What are the three code changes needed?",
        a: "Change 1: Remove the window accumulation buffer — score each edge immediately after the GRU update. Change 2: Add per-node EMA tracking (β=0.97) — a rolling weighted average of recent anomaly scores per node, providing temporal smoothing without hard time boundaries. Change 3: Use NeighborLoader with k=10 instead of full-graph forward passes — bounds computation per event to O(k) regardless of total graph size.",
      },
      {
        q: "What is Exponential Moving Average (EMA) and why use it here?",
        a: "EMA is a running weighted average where recent values matter more. Formula: ema_t = β × ema_{t-1} + (1-β) × score_t. With β=0.97, the current score contributes 3% and the historical average contributes 97%. This means a single noisy spike doesn't trigger an alert, but a sustained series of elevated scores — a real multi-step attack — accumulates above the threshold. It replaces KAIROS's discrete window with a continuous, time-decaying signal.",
      },
      {
        q: "What threshold do we set for alerting?",
        a: "Two thresholds: (1) Per-edge hard threshold — the 99.9th percentile of validation scores on a held-out benign day. Any single edge exceeding this fires immediately. (2) Per-node EMA soft threshold — set at the maximum EMA observed on the same validation day. Sustained elevation above this triggers investigation. The EVT-calibrated threshold (Generalised Pareto Distribution on the score tail) provides a theoretically principled alternative for the thesis evaluation comparison.",
      },
    ],
    code: `# The key change: score IMMEDIATELY after each event
# (previously: accumulate in window buffer, then score in batch)

class StreamingInferenceEngine:
    def __init__(self, model, threshold_hard, threshold_ema, beta=0.97):
        self.model     = model
        self.t_hard    = threshold_hard   # 99.9th pctile of validation scores
        self.t_ema     = threshold_ema    # max validation EMA
        self.beta      = beta             # EMA smoothing factor
        self.node_ema  = {}               # node_id → running EMA score

    def process_event(self, event: SysmonEvent) -> Alert | None:
        src, dst = event.src_node_id, event.dst_node_id

        # 1. Sample k=10 recent temporal neighbours for src and dst
        subgraph = self.sample_local_neighbourhood([src, dst], k=10)

        # 2. Forward pass on local subgraph only (not full graph)
        with torch.no_grad():
            z = self.model.encode(subgraph)           # [N_local, 64]
            p_exists, p_type = self.model.decode(
                z[src], z[dst]
            )

        # 3. Compute per-edge anomaly score with IDF weighting
        idf = self.get_idf_weight(event.src_type,
                                   event.edge_type,
                                   event.dst_type)
        score = anomaly_score(p_exists, p_type,
                              actual_exists=1.0,
                              actual_type=event.edge_type,
                              idf_weight=idf)

        # 4. Update per-node EMA
        for node_id in [src, dst]:
            prev = self.node_ema.get(node_id, 0.0)
            self.node_ema[node_id] = self.beta * prev + (1-self.beta) * score

        # 5. Alert if threshold exceeded
        if score > self.t_hard or self.node_ema[dst] > self.t_ema:
            return Alert(event=event, score=score,
                         ema=self.node_ema[dst], trigger="edge")
        return None`,
    sources: [
      { label: "KAIROS window latency analysis", ref: "arXiv:2308.05034 §5.4 + §5.6", note: "Windows process in ~1s for <10K edges; detection latency = full window duration." },
      { label: "ORCHID per-event approach", ref: "arXiv:2408.13347 §4", note: "Achieves 0.002s/event via GRU-only streaming. Confirms edge-level feasibility." },
      { label: "EVT threshold calibration", ref: "Pickands-Balkema-de Haan theorem (EVT)", note: "Generalised Pareto Distribution for extreme value thresholding in anomaly detection." },
    ],
  },

  drift: {
    color: C.orange,
    title: "Online drift adaptation — 3 tiers, implemented in order",
    tldr: "System behaviour changes over time (software updates, new users, seasonal patterns). These three mechanisms keep the model's definition of 'normal' current without forgetting old knowledge.",
    analogy: {
      icon: "🌱",
      title: "Like a human expert who keeps learning but doesn't forget",
      body: `A new security analyst joins your team in January.
She spends the first month learning normal system behaviour.

In February, the company deploys a new monitoring tool.
This tool creates new, legitimate process patterns she's never seen.
She recognises these are normal and updates her understanding.

In April, she encounters a real attack that looks similar to
some of the February monitoring tool patterns — but subtly different.
She catches it because she adapted (learned new normals) 
but also REMEMBERED her original training.

The challenge is called 'catastrophic forgetting':
naive re-training causes the model to forget what it learned
in January when it trains on February's data.
These three mechanisms prevent that.

Tier 1 — EMA of model weights:    implicit smoothing, free
Tier 2 — Reservoir replay:        remember the past explicitly
Tier 3 — Knowledge distillation:  keep old decision boundaries`,
    },
    tiers: [
      {
        num: "1",
        name: "EMA of model weights",
        effort: "2 days",
        color: C.green,
        desc: "Maintain a shadow copy of all model weights as an exponential moving average (β=0.999). Use the shadow copy for inference. The training copy adapts quickly; the shadow copy smooths out noise.",
        math: "θ_ema ← 0.999 × θ_ema + 0.001 × θ_new",
        note: "20 lines of PyTorch. Doubles parameter memory (~10 MB extra). No accuracy cost. Provides implicit regularisation against abrupt jumps.",
      },
      {
        num: "2",
        name: "Reservoir replay + suspicion filter",
        effort: "1–2 weeks",
        color: C.amber,
        desc: "Maintain a fixed 100K-edge replay buffer (reservoir sampling for time-uniform coverage). When fine-tuning on new data, mix 30% replay + 70% new. Critically: exclude edges from suspicious nodes to prevent learning attack patterns.",
        math: "suspicion[B] = max(suspicion[B], suspicion[A] × 0.9) when A→B",
        note: "The suspicion filter is the key provenance-specific insight from METANOIA — without it, you risk training on attack edges during adaptation. Nodes reachable from external network connections start at suspicion=1.0; internal process nodes start at 0.0.",
      },
      {
        num: "3",
        name: "Knowledge distillation",
        effort: "1–2 weeks",
        color: C.red,
        desc: "During fine-tuning, keep the previous model frozen as a 'teacher'. Add a KD loss term that penalises the new model for changing its edge-type probability distributions too much from the teacher's predictions.",
        math: "L_total = L_reconstruction + λ × KL(P_new ‖ P_old.detach())",
        note: "λ=0.1–0.5 balances plasticity and stability. KL divergence is the standard measure of 'how different are two probability distributions'. The teacher is frozen (.detach() in PyTorch) so gradients only update the student.",
      },
    ],
    faqs: [
      {
        q: "What is 'catastrophic forgetting'?",
        a: "When a neural network trains on new data, gradient descent updates its weights toward minimising loss on that new data — which typically increases loss on old data that is no longer in the training batch. The model 'forgets' what it learned before. For a security system, this is dangerous: forgetting old benign patterns causes the retrained model to suddenly flag old normal behaviour as anomalous.",
      },
      {
        q: "Why not just retrain from scratch on a merged dataset?",
        a: "Retraining from scratch requires storing and replaying all historical training data, which grows unboundedly over months or years. It also requires restarting training from random weights rather than fine-tuning — much longer training time. The three-tier approach provides a computationally bounded alternative that preserves most historical knowledge with a fixed-size replay buffer (100K edges = ~20 MB).",
      },
      {
        q: "What is Knowledge Distillation (KD)?",
        a: "Knowledge Distillation uses one model (teacher) to guide the training of another (student). The student is penalised not only for predicting wrong edge types but also for predicting edge types differently than the teacher. Since the teacher was already well-trained on old data, this anchors the student's behaviour near the old decision boundary while still allowing it to adapt. KL(P_new ‖ P_old) measures how different the two models' predictions are — high KL means they disagree significantly, which the λ term discourages.",
      },
      {
        q: "What is 'reservoir sampling'?",
        a: "Reservoir sampling is an algorithm for maintaining a random sample of a data stream with fixed memory. For each new edge arriving, with probability min(1, buffer_size / total_edges_seen), it replaces a random existing edge in the buffer. This guarantees that after N total edges, the buffer contains a uniform random sample of all N edges — giving time-uniform coverage without storing the entire stream.",
      },
      {
        q: "How does METANOIA handle drift and how are we different?",
        a: "METANOIA uses a more sophisticated 'suspicious state transfer' mechanism with explicit graph reachability computation per node. Our approach is simpler: a scalar suspicion score with exponential decay propagation (suspicion[B] = max(suspicion[B], suspicion[A] × 0.9)). METANOIA also operates within a window framework — it adapts but still requires full window completion before detection. We combine simplified adaptation with per-event scoring.",
      },
    ],
    sources: [
      { label: "METANOIA lifelong learning", ref: "arXiv:2501.00438 §4", note: "Core reference for drift adaptation in provenance IDS. Improves KAIROS precision 30–54%." },
      { label: "Replay vs EWC on graphs", ref: "arXiv:2402.11565 (Continual Learning on Graphs survey)", note: "Replay-based methods outperform regularisation-based (EWC) on graph tasks empirically." },
      { label: "Knowledge distillation", ref: "Hinton et al., 2015 (arXiv:1503.02531)", note: "Original KD paper. Soft targets via KL divergence." },
      { label: "EMA of weights", ref: "arXiv:2411.18704", note: "Analysis of EMA stability benefits in deep learning training." },
    ],
  },

  scoring: {
    color: C.green,
    title: "Four scoring improvements — compounding false positive reduction",
    tldr: "Your base reconstruction error score treats all edges equally. Four targeted modifications reduce false alarms by an estimated 60–80% by giving the model context about what 'unusual but benign' looks like.",
    analogy: {
      icon: "📊",
      title: "Like adjusting an alarm system for your specific neighbourhood",
      body: `A naive home alarm triggers on any motion.
In a quiet suburb at 3AM, any motion is suspicious.
In a busy city street, cars passing every 30 seconds are normal.

You could add context:
  ① Weight by rarity:   motion on THIS street is common, don't alarm
  ② Calibrate threshold: set sensitivity based on THIS home's history
  ③ Cluster false trips: the raccoon trips the alarm every Tuesday night
  ④ Know the context:   3AM motion vs 9AM motion should be weighted differently

These four improvements are directly analogous to your four scoring changes.
Each targets a different source of false positives.
Applied together they compound dramatically.`,
    },
    improvements: [
      {
        num: "①",
        name: "IDF-weighted scores",
        source: "KAIROS §3.4 + CAPTAIN §4.2",
        color: C.blue,
        effort: "3–5 days",
        reduction: "20–35% of FPs",
        desc: "Multiply each edge's reconstruction error by the inverse document frequency of its (src_type, edge_type, dst_type) pattern. Common benign patterns (e.g., svchost.exe WRITE to *.log) get suppressed. Rare patterns (powershell.exe FORK to unknown binary) get amplified.",
        math: "score = reconstruction_error × log(N_total / count(src_type, edge_type, dst_type))",
        why: "A cron job writes to the same log file 1000 times a day. Without IDF, each write generates a high-ish reconstruction error (it is a slightly unusual path). With IDF, these 1000 frequent writes get suppressed to near-zero. The same suppression doesn't apply to a novel powershell → network socket connection seen only twice in training.",
      },
      {
        num: "②",
        name: "EVT-calibrated threshold",
        source: "ORTHRUS USENIX 2025 + EVT theory",
        color: C.teal,
        effort: "1 week",
        reduction: "Principled vs arbitrary",
        desc: "Reserve one full day of DARPA TC benign data as validation. Fit a Generalised Pareto Distribution (GPD) to the tail of the validation score distribution. Set detection threshold at the 10⁻⁴ survival probability of the GPD. Compare to ORTHRUS's simpler maximum-validation-score approach.",
        math: "threshold = GPD_quantile(scores_validation, 1 - 10⁻⁴)",
        why: "An arbitrary threshold (e.g., 'anything above 0.5 is an alert') has no statistical justification. The EVT approach says: 'if the model was perfect, what score would occur less than once every 10,000 edges by chance?' That is a principled threshold. This is a meaningful thesis contribution — you can compare EVT vs. maximum-validation-score in your evaluation.",
      },
      {
        num: "③",
        name: "Two-stage outlier clustering",
        source: "ORTHRUS USENIX 2025 §4.3",
        color: C.purple,
        effort: "1–2 weeks",
        reduction: "Largest single contributor",
        desc: "After thresholding, collect all flagged edges within an evaluation window. Extract their edge embeddings (z_src ‖ z_dst vectors). Apply K-means (K=2). The smaller, higher-scoring cluster is 'malicious'; the larger cluster is 'benign-but-rare'. Only alert on the malicious cluster.",
        math: "K-means(flagged_edge_embeddings, K=2) → C_malicious, C_benign_rare",
        why: "Cron jobs, software update checks, and anti-virus scans produce edges that are legitimately unusual (low IDF) but completely benign. Without clustering, these trigger alerts. With clustering, they form their own cohesive cluster (similar embeddings, similar patterns) which the algorithm separates from the structurally different malicious cluster. ORTHRUS reports this as their primary FP reduction mechanism.",
      },
      {
        num: "④",
        name: "Contextual feature augmentation",
        source: "CAPTAIN arXiv:2404.14720 §4.1",
        color: C.amber,
        effort: "1–2 weeks",
        reduction: "15–25% of FPs",
        desc: "Expand the EdgeDecoder input with three contextual features: time-of-day (sin/cos encoding), node degree, and historical edge-type frequency. These give the decoder the context to produce lower scores for contextually normal events.",
        math: "edge_input = concat(z_src, z_dst, sin(2πt/86400), cos(2πt/86400), log(degree_src), log(degree_dst), log_freq)",
        why: "A scheduled task runs 'certutil.exe -urlcache' every night at 2AM. Without time encoding, the model treats every occurrence identically — and the novelty of the network connection triggers a high score. With time encoding, the model learns that CERTUTIL + CONNECT + 2AM is a recurring normal pattern. Time encoding is trivially cheap (2 extra numbers) but addresses a significant source of false alarms in production environments.",
      },
    ],
    faqs: [
      {
        q: "What is IDF (Inverse Document Frequency)?",
        a: "IDF is a weight that is HIGH for rare patterns and LOW for common patterns. Formula: IDF(pattern) = log(N_total / count(pattern)). If (svchost, WRITE, *.log) occurs 10,000 times in training, IDF ≈ log(1M / 10K) = log(100) ≈ 2. If (powershell, FORK, unknown_binary) occurs 5 times in training, IDF ≈ log(1M / 5) = log(200K) ≈ 5.3. Multiplying reconstruction errors by IDF means rare patterns get 2.6× more weight in the final alert score.",
      },
      {
        q: "What is Extreme Value Theory (EVT)?",
        a: "EVT is a branch of statistics that models the behaviour of extreme (tail) values. The Pickands–Balkema–de Haan theorem shows that above a high threshold, the tail of almost any distribution converges to a Generalised Pareto Distribution (GPD). For anomaly detection: fit a GPD to the tail of your validation anomaly scores. Then ask: 'what score is so extreme it would occur less than 1 in 10,000 times under the benign distribution?' That score is your detection threshold. It's theoretically principled in a way that 'use the 99th percentile' is not.",
      },
      {
        q: "How much do these improvements compound?",
        a: "The improvements target different false positive sources. IDF suppresses repetitive benign events (high frequency, moderate reconstruction error). EVT eliminates the arbitrary threshold problem. Two-stage clustering separates benign-rare from malicious-rare. Contextual features address time-dependent and degree-dependent patterns. Because they target different FP sources, they compound roughly multiplicatively rather than additively. Individual reductions of 20–35% each compound to 60–80% total.",
      },
    ],
    sources: [
      { label: "KAIROS IDF scoring", ref: "arXiv:2308.05034 §3.4", note: "Uses edge-type frequency weighting in anomaly score calculation." },
      { label: "CAPTAIN gradient-to-rules", ref: "arXiv:2404.14720 §4", note: "Per-edge adaptive scoring. 93% FP reduction vs. static thresholds." },
      { label: "ORTHRUS two-stage detection", ref: "USENIX Security 2025 §4.3", note: "Rarity ≠ maliciousness; clustering separates benign-rare from attack edges." },
      { label: "EVT for anomaly detection", ref: "Siffer et al., KDD 2017 (SPOT algorithm)", note: "Streaming EVT-based threshold setting with GPD fitting." },
    ],
  },

  memory: {
    color: C.amber,
    title: "Bounded memory design — keeping the graph finite",
    tldr: "A growing provenance graph accumulates nodes and edges indefinitely. Three mechanisms cap memory to ~2.6 GB regardless of stream length — within T4 VRAM limits.",
    analogy: {
      icon: "🗂️",
      title: "Like a librarian who keeps only what's been borrowed recently",
      body: `A library has space for 50,000 books (your VRAM budget).
New books arrive every day (new provenance events).
You can't keep every book ever written.

The librarian's strategy:
  ① When a book hasn't been borrowed in 6 months → move it to off-site storage
     (LRU eviction: inactive node embeddings → CPU RAM)

  ② Only keep the last 30 minutes of 'new arrivals' shelf accessible
     (Sliding adjacency window: only recent edges in GPU memory)

  ③ When the same book arrives 100 times in one day, record it as
     "100 copies of Book X" instead of 100 separate entries
     (Temporal edge coarsening: collapse repeated edges)

The books are always there if you need them (in CPU RAM or disk).
But the active reading room stays within its 50,000-book capacity.`,
    },
    mechanisms: [
      {
        name: "LRU node eviction",
        limit: "2M active nodes → 512 MB",
        color: C.blue,
        desc: "Maintain node embedding dictionary with fixed capacity (2M slots). When full, evict the least-recently-updated node's embedding to CPU RAM. On cache miss, reload from CPU. For E3-THEIA's 690K total nodes, 2M provides 3× headroom with zero eviction during normal operation.",
        code: `# Simplified LRU eviction using Python's OrderedDict
from collections import OrderedDict

class LRUNodeStore:
    def __init__(self, capacity=2_000_000, dim=64):
        self.capacity = capacity
        self.cache = OrderedDict()  # node_id → embedding on GPU

    def get(self, node_id):
        if node_id in self.cache:
            self.cache.move_to_end(node_id)  # mark as recently used
            return self.cache[node_id]
        return torch.zeros(64)  # unseen node: zero-initialised

    def put(self, node_id, embedding):
        if node_id in self.cache:
            self.cache.move_to_end(node_id)
        self.cache[node_id] = embedding
        if len(self.cache) > self.capacity:
            self.cache.popitem(last=False)  # evict least recently used`,
      },
      {
        name: "Sliding adjacency window",
        limit: "30 minutes → ~40 MB",
        color: C.teal,
        desc: "Keep only the most recent 30 minutes of edges in GPU memory for GAT neighbour sampling. Older edges are discarded — their information is already encoded in GRU hidden states. At E3-THEIA rates (~120K–500K edges per 30 minutes), this costs 10–40 MB in COO (coordinate) format.",
        code: `import time
from collections import deque

class SlidingEdgeWindow:
    def __init__(self, window_seconds=1800):  # 30 minutes
        self.window = deque()         # (timestamp, src, dst, type)
        self.window_size = window_seconds
        self.edge_index = []          # [2, E] for GAT NeighborLoader

    def add_edge(self, src, dst, edge_type, t=None):
        t = t or time.time()
        self.window.append((t, src, dst, edge_type))
        self.edge_index.append([src, dst])
        self._evict_old(t)

    def _evict_old(self, now):
        while self.window and (now - self.window[0][0]) > self.window_size:
            self.window.popleft()
        # Rebuild edge_index from current window (batched, not per-event)
        # In production: use a more efficient incremental structure`,
      },
      {
        name: "Temporal edge coarsening",
        limit: "30–60% edge count reduction",
        color: C.purple,
        desc: "Collapse repeated (src, dst, edge_type) triples within 1-minute intervals into a single weighted edge. Attacks create novel edge types or novel node pairs — not repetitions of existing patterns. Coarsening eliminates noise without losing attack signal.",
        code: `from collections import defaultdict

class EdgeCoarsener:
    def __init__(self, interval_seconds=60):
        self.interval = interval_seconds
        # (bucket, src, dst, type) → count
        self.buckets = defaultdict(int)

    def add(self, src, dst, edge_type, timestamp):
        bucket = int(timestamp // self.interval)
        key = (bucket, src, dst, edge_type)
        self.buckets[key] += 1
        # Only yield a new edge if this is the FIRST occurrence
        return self.buckets[key] == 1  # True = new, False = coarsened`,
      },
    ],
    budget: [
      { component: "Node embeddings (2M × 64)",  size: "512 MB", note: "Fixed cap via LRU" },
      { component: "GAT + GRU + Decoder params", size: "~5 MB",  note: "~200K parameters" },
      { component: "EMA model copy",             size: "~5 MB",  note: "Drift adaptation tier 1" },
      { component: "Replay buffer (100K edges)", size: "~20 MB", note: "Drift adaptation tier 2" },
      { component: "Adjacency window (30 min)",  size: "~40 MB", note: "Sliding window" },
      { component: "Training intermediates",     size: "~2 GB",  note: "Gradients + mini-batch activations" },
      { component: "TOTAL",                      size: "~2.6 GB",note: "6× headroom on T4 (16 GB)" },
    ],
    faqs: [
      {
        q: "How far is 2.6 GB from production requirements?",
        a: "The 'Are We There Yet?' (CCS 2023) survey of 20 P-EDR systems found industry expects <20 MB server-side per host. At 2.6 GB, the system is ~130× over budget. Acknowledge this explicitly in the thesis. Include an ablation: at 16-dim INT8-quantised embeddings with aggressive LRU (40K active nodes), memory drops to ~25 MB with measurable accuracy degradation that you report experimentally. This demonstrates awareness of the gap without pretending to solve it in a graduation thesis.",
      },
      {
        q: "Why does T4 have 16 GB but we only use 2.6 GB?",
        a: "Training requires significantly more memory than inference: forward activations for the mini-batch (~1.5 GB), gradient tensors (~5 MB), optimizer states (2× model parameters for Adam = ~10 MB). The 2.6 GB estimate is the inference footprint. During training, budget 4–6 GB total. The remaining 10+ GB on T4 provides headroom for larger batch sizes, which speed up training.",
      },
    ],
    sources: [
      { label: "ORCHID memory design", ref: "arXiv:2408.13347 §5.4", note: "2.7 GB for full versioned GNN. Node versioning with LRU as bounded-memory strategy." },
      { label: "Are We There Yet?", ref: "arXiv:2307.08349 (CCS 2023)", note: "<20 MB/host expectation from 10 industry managers averaging 10.5 years experience." },
      { label: "TGN memory module", ref: "arXiv:2006.10637 §3", note: "Per-node memory with bounded capacity for temporal graph networks." },
    ],
  },

  roadmap: {
    color: C.pink,
    title: "12-week Kaggle implementation roadmap",
    tldr: "Four Kaggle sessions of 3 weeks each. Every session ends with a saved checkpoint. Dependencies flow strictly forward — earlier phases must pass before starting later ones.",
    weeks: [
      {
        phase: "Phase 1",
        range: "Weeks 1–3",
        color: C.blue,
        title: "Working streaming detector",
        goal: "End-to-end loss goes down. Per-edge scores computed. No crashes.",
        tasks: [
          "Reduce GAT from 2 layers to 1. Reduce dims from 128 to 64. Verify parameter count ~200K.",
          "Implement NeighborLoader(k=10) for local neighbourhood sampling.",
          "Replace window accumulation with per-edge scoring + EMA tracking.",
          "Run on StreamSpot (simple 600-graph dataset). Confirm BCE + CE loss decreases.",
          "Save checkpoint at end of Kaggle session.",
        ],
        deliverable: "Confirmed: loss decreases. Per-edge anomaly scores computed. Architecture verified.",
      },
      {
        phase: "Phase 2",
        range: "Weeks 4–6",
        color: C.teal,
        title: "Scoring improvements + DARPA pretraining",
        goal: "IDF weighting implemented. EVT threshold calibrated. Trained on DARPA E3 benign.",
        tasks: [
          "Compute IDF weights from StreamSpot training data. Verify score distribution shifts correctly.",
          "Write darpa_loader.py — CDM JSON → PyG Data objects (this is the hardest data engineering task).",
          "Run Phase 1 pretraining on DARPA E3 benign traces (~2–3h on T4).",
          "Implement EVT threshold calibration on held-out validation day.",
          "Implement two-stage K-means clustering on flagged edges.",
        ],
        deliverable: "darpa_loader.py working. Phase 1 checkpoint trained on DARPA E3. FP rate measured.",
      },
      {
        phase: "Phase 3",
        range: "Weeks 7–9",
        color: C.orange,
        title: "Drift adaptation + memory bounds",
        goal: "Three-tier drift adaptation implemented. Memory budget verified within 3 GB.",
        tasks: [
          "Implement EMA of model weights (2 days).",
          "Implement reservoir replay buffer with suspicion-based filtering.",
          "Implement KD regularisation term (L_total = L_recon + λ × KL).",
          "Implement LRU node eviction (cap at 2M nodes).",
          "Implement sliding adjacency window (30-minute buffer).",
          "Simulate concept drift: train on E3-week1 benign, adapt to E3-week2, measure FP drift.",
        ],
        deliverable: "Drift adaptation working. Memory budget <3 GB verified. Drift experiment shows improvement over static model.",
      },
      {
        phase: "Phase 4",
        range: "Weeks 10–12",
        color: C.pink,
        title: "Evaluation + thesis writing",
        goal: "All metrics computed. Comparison table against KAIROS ready. Thesis chapters written.",
        tasks: [
          "Run evaluation on DARPA TC E3 attack traces. Record recall, precision, FPR, latency.",
          "Ablation study: disable each scoring improvement individually, measure FP impact.",
          "Latency measurement: 100 consecutive edge insertions, mean ± std. Use torch.cuda.synchronize().",
          "Compare against published KAIROS numbers (recall 100%, FPR 0.054%).",
          "Write thesis sections: system design, implementation, evaluation, discussion.",
        ],
        deliverable: "Complete evaluation table. Thesis draft ready for supervisor review.",
      },
    ],
    faqs: [
      {
        q: "What is the single most important thing to verify in Week 1?",
        a: "That loss decreases on StreamSpot. If the BCE + CE training loss does not decrease over 10 epochs, something is wrong with the data pipeline, the model, or the training loop — and everything downstream is built on broken foundations. StreamSpot is chosen specifically because it is small (600 graphs) and simple (benign vs. attack is clearly separable). It is a sanity check, not a real evaluation.",
      },
      {
        q: "What is the hardest engineering task in the roadmap?",
        a: "Writing darpa_loader.py. DARPA TC E3 data is stored as CDM-format JSON records, each event as a separate JSON object with UUIDs for node references. Building the PyG Data object requires: (1) parsing all CDM records into a node registry (UUID → feature vector), (2) constructing the edge COO matrix from SUBJECT_PROCESS → EVENT_* → OBJECT_* chains, (3) handling the fact that E3-THEIA alone has 32M edges across multiple files. Budget 3–5 days for this loader alone.",
      },
      {
        q: "What if the full evaluation can't match KAIROS's 100% recall?",
        a: "Report it honestly. If recall is 90%, write: 'Ophanim-EDR achieves 90% recall compared to KAIROS's 100%, while eliminating window-boundary detection latency and demonstrating online adaptation to concept drift. The 10% recall gap represents the cost of edge-level granularity; future work could close this gap by incorporating multi-hop context aggregation over time.' A thesis requires honest measurement, not perfect results. Reviewers value intellectual honesty over cherry-picked numbers.",
      },
    ],
  },

};

/* ─── COMPONENT ─────────────────────────────────────────────────────────── */

export default function OphanimArchGuide() {
  const [activeId, setActiveId]     = useState("positioning");
  const [openFaqs, setOpenFaqs]     = useState({});
  const [openCode, setOpenCode]     = useState({});

  const sec    = CONTENT[activeId];
  const secDef = SECTIONS.find(s => s.id === activeId);

  const toggleFaq  = k => setOpenFaqs(p => ({ ...p, [k]: !p[k] }));
  const toggleCode = k => setOpenCode(p => ({ ...p, [k]: !p[k] }));

  // group sections by group label
  const groups = [];
  let lastGroup = null;
  SECTIONS.forEach(s => {
    if (s.group !== lastGroup) { groups.push({ label: s.group, items: [] }); lastGroup = s.group; }
    groups[groups.length - 1].items.push(s);
  });

  return (
    <div style={{ fontFamily: "'Fira Code','Courier New',monospace", background: "#09101f", color: "#c8d8f0", minHeight: "100vh", fontSize: 13 }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@300;400;500;600;700&family=Playfair+Display:wght@700&display=swap');
        *{box-sizing:border-box;margin:0;padding:0}
        ::-webkit-scrollbar{width:3px}::-webkit-scrollbar-thumb{background:#223;border-radius:2px}
        .nav-item{cursor:pointer;transition:all .12s;border-left:2px solid transparent}
        .nav-item:hover{background:rgba(255,255,255,.04)!important}
        .faq-row{cursor:pointer;transition:background .1s}.faq-row:hover{background:rgba(255,255,255,.03)}
        .code-btn{cursor:pointer;transition:all .12s}.code-btn:hover{opacity:.8}
        @keyframes fadeSlide{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}
        .fade{animation:fadeSlide .18s ease}
        @keyframes pulse{0%,100%{opacity:1}50%{opacity:.45}}.pulse{animation:pulse 2.2s infinite}
        pre{white-space:pre-wrap;word-break:break-word}
      `}</style>

      {/* ── TOP BAR ── */}
      <div style={{ background:"#060d1a", borderBottom:"1px solid rgba(255,255,255,.06)", padding:"11px 20px", display:"flex", alignItems:"center", gap:12 }}>
        <div style={{ width:7, height:7, borderRadius:"50%", background:"#10b981", boxShadow:"0 0 6px #10b981" }} className="pulse" />
        <span style={{ fontFamily:"'Playfair Display',serif", fontSize:15, color:"#e8f0ff", letterSpacing:".02em" }}>Ophanim-EDR</span>
        <span style={{ fontSize:8, color:"#334455", letterSpacing:".12em" }}>/ CAUSALITY ENGINE — ARCHITECTURE GUIDE</span>
      </div>

      <div style={{ display:"flex", height:"calc(100vh - 44px)", overflow:"hidden" }}>

        {/* ── SIDEBAR ── */}
        <div style={{ width:210, flexShrink:0, borderRight:"1px solid rgba(255,255,255,.06)", overflowY:"auto", background:"#070e1c", paddingBottom:24 }}>
          {groups.map(g => (
            <div key={g.label}>
              <div style={{ padding:"14px 14px 5px", fontSize:8, color:"#334455", letterSpacing:".14em" }}>{g.label}</div>
              {g.items.map(s => (
                <div key={s.id} className="nav-item"
                  onClick={() => { setActiveId(s.id); setOpenFaqs({}); setOpenCode({}); }}
                  style={{
                    padding:"9px 14px",
                    borderLeft:`2px solid ${activeId === s.id ? s.color : "transparent"}`,
                    background: activeId === s.id ? "rgba(255,255,255,.045)" : "transparent",
                  }}>
                  <div style={{ fontSize:11, color: activeId === s.id ? "#e8f0ff" : "#667788", fontWeight: activeId === s.id ? 600 : 400, lineHeight:1.4 }}>
                    {s.label}
                  </div>
                </div>
              ))}
            </div>
          ))}
        </div>

        {/* ── MAIN CONTENT ── */}
        <div style={{ flex:1, overflowY:"auto", padding:"26px 30px 48px" }}>
          {sec && secDef && (
            <div className="fade" key={activeId}>

              {/* HEADER */}
              <div style={{ marginBottom:22 }}>
                <div style={{ fontSize:8, color:secDef.color, letterSpacing:".16em", fontWeight:700, marginBottom:6 }}>
                  ◆ {secDef.group}
                </div>
                <h2 style={{ fontFamily:"'Playfair Display',serif", fontSize:22, color:"#e8f0ff", fontWeight:700, marginBottom:10, lineHeight:1.25 }}>
                  {sec.title}
                </h2>
                {/* TLDR */}
                <div style={{ background:`linear-gradient(135deg,${secDef.color}11,transparent)`, border:`1px solid ${secDef.color}28`, borderRadius:5, padding:"9px 15px", fontSize:12, color:"#c8d8f0", lineHeight:1.65 }}>
                  <span style={{ color:secDef.color, fontWeight:700, marginRight:6 }}>TL;DR</span>{sec.tldr}
                </div>
              </div>

              {/* ANALOGY */}
              {sec.analogy && (
                <div style={{ background:"rgba(255,255,255,.025)", border:"1px solid rgba(255,255,255,.07)", borderRadius:6, padding:"16px 20px", marginBottom:20 }}>
                  <div style={{ fontSize:10, color:"#8899aa", letterSpacing:".08em", fontWeight:600, marginBottom:10 }}>
                    {sec.analogy.icon}  ANALOGY — {sec.analogy.title.toUpperCase()}
                  </div>
                  <pre style={{ fontSize:11, color:"#99aabb", lineHeight:1.85, fontFamily:"'Fira Code',monospace" }}>
                    {sec.analogy.body}
                  </pre>
                </div>
              )}

              {/* PIPELINE STEPS (pipeline section) */}
              {sec.pipeline_steps && (
                <div style={{ marginBottom:20 }}>
                  {sec.pipeline_steps.map((s, i) => (
                    <div key={i} style={{ display:"flex", gap:14, alignItems:"flex-start", marginBottom:6 }}>
                      <div style={{ minWidth:30, fontSize:9, color:s.color, fontWeight:700, paddingTop:2 }}>{s.num}</div>
                      <div style={{ flex:1, background:"rgba(255,255,255,.025)", border:`1px solid ${s.color}25`, borderRadius:4, padding:"9px 14px", display:"flex", justifyContent:"space-between", alignItems:"center", gap:10 }}>
                        <span style={{ fontSize:11, fontWeight:600, color:"#ddeeff" }}>{s.name}</span>
                        <span style={{ fontSize:9, color:s.color, letterSpacing:".08em" }}>{s.dim}</span>
                        <span style={{ fontSize:10, color:"#778899", flex:1, textAlign:"right" }}>{s.desc}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* DRIFT TIERS */}
              {sec.tiers && (
                <div style={{ marginBottom:20 }}>
                  {sec.tiers.map((t, i) => (
                    <div key={i} style={{ borderLeft:`3px solid ${t.color}`, background:"rgba(255,255,255,.022)", borderRadius:"0 5px 5px 0", padding:"14px 16px", marginBottom:10 }}>
                      <div style={{ display:"flex", gap:10, alignItems:"center", marginBottom:7 }}>
                        <span style={{ fontSize:9, color:t.color, fontWeight:700 }}>TIER {t.num}</span>
                        <span style={{ fontSize:12, fontWeight:600, color:"#ddeeff" }}>{t.name}</span>
                        <span style={{ marginLeft:"auto", fontSize:9, color:"#556677" }}>{t.effort}</span>
                      </div>
                      <div style={{ fontSize:11, color:"#99aabb", lineHeight:1.75, marginBottom:8 }}>{t.desc}</div>
                      <div style={{ fontFamily:"'Fira Code',monospace", fontSize:10, color:t.color, background:"rgba(0,0,0,.3)", padding:"6px 10px", borderRadius:4, marginBottom:7 }}>
                        {t.math}
                      </div>
                      <div style={{ fontSize:10, color:"#667788", lineHeight:1.65 }}>{t.note}</div>
                    </div>
                  ))}
                </div>
              )}

              {/* SCORING IMPROVEMENTS */}
              {sec.improvements && (
                <div style={{ marginBottom:20 }}>
                  {sec.improvements.map((imp, i) => (
                    <div key={i} style={{ border:`1px solid ${imp.color}22`, borderRadius:6, padding:"14px 16px", marginBottom:10, background:"rgba(255,255,255,.018)" }}>
                      <div style={{ display:"flex", gap:10, alignItems:"center", marginBottom:6, flexWrap:"wrap" }}>
                        <span style={{ fontSize:16, color:imp.color }}>{imp.num}</span>
                        <span style={{ fontSize:12, fontWeight:600, color:"#ddeeff" }}>{imp.name}</span>
                        <span style={{ fontSize:9, background:`${imp.color}18`, color:imp.color, padding:"2px 7px", borderRadius:3, letterSpacing:".06em" }}>{imp.reduction}</span>
                        <span style={{ marginLeft:"auto", fontSize:9, color:"#445566" }}>{imp.effort}</span>
                      </div>
                      <div style={{ fontSize:10, color:"#778899", marginBottom:6, lineHeight:1.5 }}>
                        <span style={{ color:"#556677" }}>Source: </span>{imp.source}
                      </div>
                      <div style={{ fontSize:11, color:"#99aabb", lineHeight:1.75, marginBottom:8 }}>{imp.desc}</div>
                      <div style={{ fontFamily:"'Fira Code',monospace", fontSize:10, color:imp.color, background:"rgba(0,0,0,.3)", padding:"6px 10px", borderRadius:4, marginBottom:8 }}>
                        {imp.math}
                      </div>
                      <div style={{ fontSize:11, color:"#778899", lineHeight:1.7, borderTop:"1px solid rgba(255,255,255,.05)", paddingTop:8 }}>
                        <span style={{ color:"#556677" }}>Why: </span>{imp.why}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* MEMORY MECHANISMS */}
              {sec.mechanisms && (
                <div style={{ marginBottom:20 }}>
                  {sec.mechanisms.map((m, i) => (
                    <div key={i} style={{ borderLeft:`3px solid ${m.color}`, background:"rgba(255,255,255,.022)", borderRadius:"0 5px 5px 0", padding:"13px 16px", marginBottom:10 }}>
                      <div style={{ display:"flex", gap:10, alignItems:"center", marginBottom:6 }}>
                        <span style={{ fontSize:11, fontWeight:700, color:"#ddeeff" }}>{m.name}</span>
                        <span style={{ fontSize:9, color:m.color, marginLeft:"auto" }}>{m.limit}</span>
                      </div>
                      <div style={{ fontSize:11, color:"#99aabb", lineHeight:1.75, marginBottom:8 }}>{m.desc}</div>
                      <div
                        className="code-btn"
                        onClick={() => toggleCode(`mech-${i}`)}
                        style={{ fontSize:9, color:m.color, letterSpacing:".1em", marginBottom: openCode[`mech-${i}`] ? 8 : 0 }}
                      >
                        {openCode[`mech-${i}`] ? "▼ HIDE CODE" : "▷ SHOW CODE"}
                      </div>
                      {openCode[`mech-${i}`] && (
                        <div style={{ background:"#040810", borderRadius:4, padding:"14px 16px", overflowX:"auto" }}>
                          <pre style={{ fontSize:11, lineHeight:1.75, color:"#c8d8f0", fontFamily:"'Fira Code',monospace" }}>
                            {m.code.split('\n').map((line, li) => {
                              let c = "#c8d8f0";
                              const t = line.trim();
                              if (t.startsWith('#')) c = "#3d5470";
                              else if (/^(def |class |from |import |return |if |elif |else|for |while )/.test(t)) c = "#7ba3d4";
                              return <span key={li} style={{ display:"block", color:c }}>{line || "\u00a0"}</span>;
                            })}
                          </pre>
                        </div>
                      )}
                    </div>
                  ))}
                  {/* MEMORY BUDGET TABLE */}
                  {sec.budget && (
                    <div style={{ border:"1px solid rgba(251,191,36,.15)", borderRadius:6, overflow:"hidden", marginTop:16 }}>
                      <div style={{ padding:"8px 14px", background:"rgba(251,191,36,.06)", fontSize:9, color:C.amber, letterSpacing:".12em", fontWeight:700 }}>
                        MEMORY BUDGET — T4 GPU (16 GB)
                      </div>
                      {sec.budget.map((r, i) => (
                        <div key={i} style={{ display:"flex", gap:12, padding:"8px 14px", borderTop:"1px solid rgba(255,255,255,.04)", background: r.component === "TOTAL" ? "rgba(251,191,36,.06)" : "transparent" }}>
                          <span style={{ fontSize:11, color: r.component === "TOTAL" ? C.amber : "#aabbcc", flex:1, fontWeight: r.component === "TOTAL" ? 700 : 400 }}>{r.component}</span>
                          <span style={{ fontSize:11, color: r.component === "TOTAL" ? C.amber : "#60a5fa", minWidth:60, textAlign:"right", fontWeight: r.component === "TOTAL" ? 700 : 400 }}>{r.size}</span>
                          <span style={{ fontSize:10, color:"#556677", flex:1 }}>{r.note}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* ROADMAP PHASES */}
              {sec.weeks && (
                <div style={{ marginBottom:20 }}>
                  {sec.weeks.map((w, i) => (
                    <div key={i} style={{ border:`1px solid ${w.color}22`, borderRadius:6, padding:"15px 18px", marginBottom:12 }}>
                      <div style={{ display:"flex", gap:10, alignItems:"center", marginBottom:8 }}>
                        <span style={{ fontSize:9, color:w.color, fontWeight:700, letterSpacing:".1em" }}>{w.phase} · {w.range}</span>
                        <span style={{ fontSize:13, fontWeight:600, color:"#ddeeff" }}>{w.title}</span>
                      </div>
                      <div style={{ fontSize:11, color:"#778899", marginBottom:10, lineHeight:1.6 }}>
                        <span style={{ color:"#556677" }}>Goal: </span>{w.goal}
                      </div>
                      <div style={{ marginBottom:10 }}>
                        {w.tasks.map((task, ti) => (
                          <div key={ti} style={{ display:"flex", gap:8, fontSize:11, color:"#8899aa", lineHeight:1.65, marginBottom:3 }}>
                            <span style={{ color:w.color, flexShrink:0 }}>→</span>
                            <span>{task}</span>
                          </div>
                        ))}
                      </div>
                      <div style={{ fontSize:10, background:`${w.color}0d`, border:`1px solid ${w.color}25`, borderRadius:4, padding:"6px 10px", color:w.color, lineHeight:1.5 }}>
                        ✓ Deliverable: {w.deliverable}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* CODE BLOCK (single, for encoder sections) */}
              {sec.code && (
                <div style={{ marginBottom:20 }}>
                  <div
                    className="code-btn"
                    onClick={() => toggleCode("main")}
                    style={{ display:"flex", alignItems:"center", gap:8, marginBottom: openCode.main ? 0 : 4 }}
                  >
                    <span style={{ fontSize:9, color:secDef.color, letterSpacing:".12em", fontWeight:700 }}>
                      {openCode.main ? "▼ HIDE IMPLEMENTATION" : "▷ SHOW IMPLEMENTATION"}
                    </span>
                    <span style={{ fontSize:9, color:"#334455" }}>Python · PyTorch Geometric</span>
                  </div>
                  {openCode.main && (
                    <div style={{ background:"#040810", border:`1px solid ${secDef.color}20`, borderRadius:"0 0 5px 5px", padding:"16px 18px", overflowX:"auto" }}>
                      <pre style={{ fontSize:11, lineHeight:1.8, color:"#c8d8f0", fontFamily:"'Fira Code',monospace" }}>
                        {sec.code.split('\n').map((line, li) => {
                          let c = "#c8d8f0";
                          const t = line.trim();
                          if (t.startsWith('#')) c = "#3d5470";
                          else if (/^(def |class |async def )/.test(t)) c = "#a78bfa";
                          else if (/^(from |import |return |yield )/.test(t)) c = "#60a5fa";
                          else if (/^(if |elif |else:|for |while |with )/.test(t)) c = "#fb923c";
                          return <span key={li} style={{ display:"block", color:c }}>{line || "\u00a0"}</span>;
                        })}
                      </pre>
                    </div>
                  )}
                </div>
              )}

              {/* FAQ */}
              {sec.faqs && sec.faqs.length > 0 && (
                <div style={{ border:"1px solid rgba(255,255,255,.06)", borderRadius:6, overflow:"hidden", marginBottom:20 }}>
                  <div style={{ padding:"9px 16px", background:"rgba(255,255,255,.025)", fontSize:9, letterSpacing:".12em", color:"#556677", fontWeight:700 }}>
                    DEEP DIVE — CLICK TO EXPAND
                  </div>
                  {sec.faqs.map((faq, i) => {
                    const k = `${activeId}-${i}`;
                    return (
                      <div key={i} style={{ borderTop:"1px solid rgba(255,255,255,.05)" }}>
                        <div className="faq-row" onClick={() => toggleFaq(k)} style={{ padding:"11px 16px", display:"flex", justifyContent:"space-between", alignItems:"flex-start", gap:12 }}>
                          <span style={{ fontSize:11, color: openFaqs[k] ? "#ddeeff" : "#aabbcc", fontWeight: openFaqs[k] ? 600 : 400, lineHeight:1.5 }}>{faq.q}</span>
                          <span style={{ color:secDef.color, fontSize:16, flexShrink:0, lineHeight:1 }}>{openFaqs[k] ? "−" : "+"}</span>
                        </div>
                        {openFaqs[k] && (
                          <div className="fade" style={{ padding:"0 16px 13px", fontSize:11, color:"#778899", lineHeight:1.85 }}>{faq.a}</div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}

              {/* SOURCES */}
              {sec.sources && (
                <div style={{ border:"1px solid rgba(255,255,255,.05)", borderRadius:5, overflow:"hidden" }}>
                  <div style={{ padding:"7px 14px", background:"rgba(255,255,255,.02)", fontSize:9, color:"#445566", letterSpacing:".12em", fontWeight:700 }}>
                    SOURCES & CITATIONS
                  </div>
                  {sec.sources.map((s, i) => (
                    <div key={i} style={{ padding:"9px 14px", borderTop:"1px solid rgba(255,255,255,.04)", display:"flex", gap:12, alignItems:"flex-start" }}>
                      <div style={{ flex:1 }}>
                        <div style={{ fontSize:11, color:"#aabbcc", marginBottom:2, fontWeight:500 }}>{s.label}</div>
                        <div style={{ fontSize:10, color:"#4a6680", fontFamily:"'Fira Code',monospace", marginBottom:3 }}>{s.ref}</div>
                        <div style={{ fontSize:10, color:"#556677", lineHeight:1.55 }}>{s.note}</div>
                      </div>
                    </div>
                  ))}
                </div>
              )}

            </div>
          )}
        </div>

      </div>
    </div>
  );
}