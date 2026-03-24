"""
Ophanim-EDR Causality Engine — GNN encoder-decoder for provenance anomaly detection.

Architecture (confirmed, single source of truth):

    Raw event features (heterogeneous: 4-12 dims per CDM node type)
        ↓ NodeTypeProjection
    One nn.Linear per node type → 64-dim common embedding space
        ↓ 1-layer GAT
    4 heads × 16-dim = 64-dim output, k=10 neighbourhood sampling
    LayerNorm + ELU
        ↓ GRU Cell (64-dim hidden state)
    Per-node hidden state updated on every edge event
        ↓ Linear projection (64 → 64)
        ↓ EdgeDecoder
    Dual-head MLP: P(edge_exists) + P(edge_type)
        ↓ Anomaly score
    raw = BCE + CE, final = raw × IDF(src_type, edge_type, dst_type)

Design decisions documented inline. See docs/08-notebook-phase1.md for rationale.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F

# Guard PyG imports — torch-sparse fails to build on Windows.
try:
    from torch_geometric.nn import GATConv
    PYGEOMETRIC_AVAILABLE = True
except ImportError:
    PYGEOMETRIC_AVAILABLE = False


# ---------------------------------------------------------------------------
# Fallback GAT implementation (pure PyTorch, no torch-sparse dependency)
# ---------------------------------------------------------------------------

class GATConvFallback(nn.Module):
    """
    Single-head Graph Attention layer (Veličković et al., ICLR 2018).

    Pure PyTorch implementation that avoids torch-sparse. Supports multi-head
    via the caller stacking multiple instances or using MultiHeadGAT below.

    Attention mechanism:
        α_ij = softmax_j( LeakyReLU( a^T [Wh_i || Wh_j] ) )
        h'_i = Σ_j α_ij · Wh_j

    This is mathematically identical to PyG's GATConv with add aggregation.
    """

    def __init__(self, in_channels: int, out_channels: int):
        super().__init__()
        self.W = nn.Linear(in_channels, out_channels, bias=False)
        # Attention vector: applied to concatenated [Wh_i || Wh_j]
        self.attn = nn.Parameter(torch.empty(2 * out_channels))
        nn.init.xavier_uniform_(self.attn.unsqueeze(0))
        self.leaky_relu = nn.LeakyReLU(0.2)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: Node features [N, in_channels]
            edge_index: COO edge indices [2, E]
        Returns:
            Updated node features [N, out_channels]
        """
        Wh = self.W(x)  # [N, out_channels]
        src, dst = edge_index[0], edge_index[1]

        # Compute attention coefficients for each edge
        edge_feat = torch.cat([Wh[src], Wh[dst]], dim=-1)  # [E, 2*out]
        e = self.leaky_relu(edge_feat @ self.attn)  # [E]

        # Softmax over each node's incoming edges
        e_max = torch.zeros(x.size(0), device=x.device)
        e_max.scatter_reduce_(0, dst, e, reduce='amax', include_self=True)
        e_stable = e - e_max[dst]
        alpha = torch.exp(e_stable)  # [E]

        alpha_sum = torch.zeros(x.size(0), device=x.device)
        alpha_sum.scatter_add_(0, dst, alpha)
        alpha = alpha / (alpha_sum[dst] + 1e-8)  # [E], normalized

        # Weighted aggregation
        out = torch.zeros_like(Wh)
        out.scatter_add_(0, dst.unsqueeze(-1).expand_as(Wh[src]), alpha.unsqueeze(-1) * Wh[src])
        return out


class MultiHeadGAT(nn.Module):
    """
    Multi-head GAT layer that concatenates head outputs.

    With 4 heads × 16-dim = 64-dim output, matching KAIROS's configuration.
    One layer is used instead of two because:
      - 97% of E3-THEIA nodes have ≤20 neighbours (ORCHID §5.2)
      - A second layer expands receptive field to k²=100 nodes
      - This is ~10× more computation for minimal accuracy gain
      - Single-layer already captures the relevant 1-hop neighbourhood
    """

    def __init__(self, in_channels: int, out_channels_per_head: int, num_heads: int):
        super().__init__()
        self.num_heads = num_heads
        self.out_per_head = out_channels_per_head

        if PYGEOMETRIC_AVAILABLE:
            self.gat = GATConv(
                in_channels, out_channels_per_head,
                heads=num_heads, concat=True
            )
        else:
            self.heads = nn.ModuleList([
                GATConvFallback(in_channels, out_channels_per_head)
                for _ in range(num_heads)
            ])

        self.norm = nn.LayerNorm(out_channels_per_head * num_heads)

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        if PYGEOMETRIC_AVAILABLE:
            out = self.gat(x, edge_index)
        else:
            head_outs = [head(x, edge_index) for head in self.heads]
            out = torch.cat(head_outs, dim=-1)  # [N, heads * out_per_head]

        return F.elu(self.norm(out))


# ---------------------------------------------------------------------------
# Main model components
# ---------------------------------------------------------------------------

class NodeTypeProjection(nn.Module):
    """
    Projects heterogeneous node features into a common 64-dim embedding space.

    Each CDM node type has different raw feature dimensions (process=8, file=4,
    socket=6, registry=5, memory=4, other=3). A per-type linear layer maps each
    to the same 64-dim space so downstream layers can process them uniformly.

    This is equivalent to KAIROS's type-specific input projection, and standard
    practice for heterogeneous GNNs (Schlichtkrull et al., ESWC 2018).
    """

    def __init__(self, feature_dims: dict, embed_dim: int = 64):
        super().__init__()
        self.embed_dim = embed_dim
        self.projections = nn.ModuleDict({
            str(type_id): nn.Linear(feat_dim, embed_dim)
            for type_id, feat_dim in feature_dims.items()
        })

    def forward(self, x: torch.Tensor, node_types: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: Padded node features [N, max_feat_dim]. Each row is zero-padded
               to the maximum feature dimension across all types.
            node_types: Integer type IDs [N].
        Returns:
            Projected embeddings [N, embed_dim].
        """
        out = torch.zeros(x.size(0), self.embed_dim, device=x.device)
        for type_id, proj in self.projections.items():
            mask = (node_types == int(type_id))
            if mask.any():
                feat_dim = proj.in_features
                out[mask] = proj(x[mask, :feat_dim])
        return out


class TemporalEncoder(nn.Module):
    """
    GAT + GRU encoder for temporal provenance graphs.

    Combines spatial context (GAT over node neighbourhood) with temporal
    evolution (GRU maintaining per-node hidden state across events).

    The GRU is chosen over LSTM because:
      - ~25% fewer parameters (no separate cell state)
      - KAIROS validates that GRU is sufficient for provenance temporal modelling
      - The hidden state serves as a "memory" of past events per node

    64-dim hidden state (not 128) because:
      - Halves memory per node: 256 bytes vs 512 bytes at float32
      - At 690K nodes (E3-THEIA): 177 MB vs 354 MB
      - ORCHID finds diminishing returns beyond 64-dim for provenance embeddings
    """

    def __init__(self, embed_dim: int = 64, gat_heads: int = 4, gat_head_dim: int = 16):
        super().__init__()
        assert gat_heads * gat_head_dim == embed_dim, \
            f"GAT output dim ({gat_heads}×{gat_head_dim}) must equal embed_dim ({embed_dim})"

        self.gat = MultiHeadGAT(embed_dim, gat_head_dim, gat_heads)
        self.gru = nn.GRUCell(embed_dim, embed_dim)
        self.proj = nn.Linear(embed_dim, embed_dim)

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        h: torch.Tensor | None = None,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        """
        Args:
            x: Node embeddings [N, embed_dim] (output of NodeTypeProjection)
            edge_index: COO edge indices [2, E]
            h: Previous hidden state [N, embed_dim], or None for initial
        Returns:
            z: Updated node embeddings [N, embed_dim]
            h_new: New hidden state [N, embed_dim]
        """
        # Spatial context via GAT
        spatial = self.gat(x, edge_index)  # [N, embed_dim]

        # Temporal update via GRU
        if h is None:
            h = torch.zeros_like(spatial)
        h_new = self.gru(spatial, h)  # [N, embed_dim]

        # Linear projection (preserves dimension)
        z = self.proj(h_new)  # [N, embed_dim]
        return z, h_new


class EdgeDecoder(nn.Module):
    """
    Dual-head MLP decoder for edge prediction.

    Takes concatenated source and destination node embeddings (128-dim)
    and produces two outputs:
      Head 1: P(edge_exists) — binary, sigmoid activation
      Head 2: P(edge_type)   — 9-class softmax (CDM edge types)

    The dual-head design follows KAIROS's approach: edge existence captures
    whether a connection is expected at all, while edge type captures whether
    the *kind* of connection is expected. Both signals contribute to anomaly
    scoring because an attacker may create unexpected connections (existence)
    or repurpose legitimate connections for unexpected operations (type).

    Architecture:
        concat(z_src, z_dst) = 128-dim
        → Linear(128→128) → ELU → Dropout(0.1)
        → Linear(128→64)  → ELU
        → Head 1: Linear(64→1)  + sigmoid
        → Head 2: Linear(64→9)  + log_softmax
    """

    def __init__(self, embed_dim: int = 64, num_edge_types: int = 9, dropout: float = 0.1):
        super().__init__()
        self.trunk = nn.Sequential(
            nn.Linear(embed_dim * 2, embed_dim * 2),
            nn.ELU(),
            nn.Dropout(dropout),
            nn.Linear(embed_dim * 2, embed_dim),
            nn.ELU(),
        )
        self.head_exists = nn.Linear(embed_dim, 1)
        self.head_type = nn.Linear(embed_dim, num_edge_types)

    def forward(
        self, z: torch.Tensor, edge_index: torch.Tensor
    ) -> tuple[torch.Tensor, torch.Tensor]:
        """
        Args:
            z: Node embeddings [N, embed_dim]
            edge_index: COO edge indices [2, E]
        Returns:
            p_exists: Edge existence logits [E, 1]
            p_type: Edge type log-probabilities [E, num_edge_types]
        """
        src, dst = edge_index[0], edge_index[1]
        edge_feat = torch.cat([z[src], z[dst]], dim=-1)  # [E, 2*embed_dim]
        trunk_out = self.trunk(edge_feat)  # [E, embed_dim]

        p_exists = self.head_exists(trunk_out)  # [E, 1] — raw logits
        p_type = F.log_softmax(self.head_type(trunk_out), dim=-1)  # [E, num_types]
        return p_exists, p_type


class CausalityEncoder(nn.Module):
    """
    Complete encoder-decoder model combining all components.

    This is the top-level module used for training and inference.
    Wraps NodeTypeProjection + TemporalEncoder + EdgeDecoder into a single
    forward pass that goes from raw features to edge predictions.
    """

    def __init__(
        self,
        feature_dims: dict,
        embed_dim: int = 64,
        gat_heads: int = 4,
        gat_head_dim: int = 16,
        num_edge_types: int = 9,
        dropout: float = 0.1,
    ):
        super().__init__()
        self.node_proj = NodeTypeProjection(feature_dims, embed_dim)
        self.encoder = TemporalEncoder(embed_dim, gat_heads, gat_head_dim)
        self.decoder = EdgeDecoder(embed_dim, num_edge_types, dropout)

    def forward(
        self,
        x: torch.Tensor,
        node_types: torch.Tensor,
        edge_index: torch.Tensor,
        h: torch.Tensor | None = None,
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Full forward pass: features → embeddings → edge predictions.

        Returns:
            p_exists: [E, 1] edge existence logits
            p_type: [E, num_types] edge type log-probs
            h_new: [N, embed_dim] updated hidden state
        """
        emb = self.node_proj(x, node_types)
        z, h_new = self.encoder(emb, edge_index, h)
        p_exists, p_type = self.decoder(z, edge_index)
        return p_exists, p_type, h_new
