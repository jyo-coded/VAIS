"""
ml/gnn_model.py
───────────────
AST-based Graph Neural Network for vulnerability detection.

Architecture
─────────────
  Input  : AST graphs from Tree-sitter (one graph per function)
  Nodes  : AST node types one-hot encoded + depth + is_call_node flag
  Edges  : Parent → child directed edges (bidirectional for GCN)
  Model  : 3-layer GCN → global mean pool → 2-class linear head
  Hidden : 128
  Dropout: 0.30
  Output : P(vulnerable)  in [0, 1]

Saved to : models/gnn_vuln.pt

Public API
──────────
  ast_to_data(ast_json)           -> torch_geometric.data.Data
  train_gnn(dataset_result, ...)  -> GNNPredictor
  GNNPredictor.predict(ast_json)  -> float
  GNNPredictor.load(path)         -> GNNPredictor
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import numpy as np

log = logging.getLogger(__name__)

DEFAULT_OUT_PATH = "models/gnn_vuln.pt"

# ─── Node type vocabulary ─────────────────────────────────────────────────────
# Populated lazily from training data; pre-seeded with universal AST node names.
_COMMON_NODE_TYPES = [
    "translation_unit", "function_definition", "function_declarator",
    "parameter_list", "parameter_declaration", "compound_statement",
    "declaration", "expression_statement", "return_statement",
    "if_statement", "while_statement", "for_statement", "do_statement",
    "call_expression", "assignment_expression", "binary_expression",
    "unary_expression", "subscript_expression", "pointer_expression",
    "field_expression", "cast_expression", "sizeof_expression",
    "identifier", "number_literal", "string_literal", "char_literal",
    "true", "false", "null", "comment",
    "type_identifier", "primitive_type", "pointer_declarator",
    "init_declarator", "initializer_list",
    "new_expression", "delete_expression",
    "method_invocation", "object_creation_expression",
    "local_variable_declaration", "field_declaration",
    "class_declaration", "method_declaration",
    "try_statement", "catch_clause", "throw_statement",
    "import_declaration", "package_declaration",
]

NODE_TYPE_TO_IDX: dict[str, int] = {t: i for i, t in enumerate(_COMMON_NODE_TYPES)}
UNKNOWN_IDX = len(_COMMON_NODE_TYPES)        # index for unseen node types
VOCAB_SIZE   = UNKNOWN_IDX + 1              # feature dim for one-hot part

# Additional binary feature indices appended after one-hot:
#   [VOCAB_SIZE]   = depth_normalised (0..1)
#   [VOCAB_SIZE+1] = is_call_node     (0/1)
NODE_FEAT_DIM = VOCAB_SIZE + 2

CALL_NODE_TYPES = {"call_expression", "method_invocation", "object_creation_expression"}

# Training hyperparameters
GNN_EPOCHS   = 30
GNN_LR       = 1e-3
GNN_BATCH    = 32
GNN_DROPOUT  = 0.30
GNN_HIDDEN   = 128
MAX_AST_NODES = 1000    # cap graph size to manage VRAM


# ─── AST → PyG Data ──────────────────────────────────────────────────────────

def ast_to_data(ast_json: dict, label: Optional[int] = None):
    """
    Convert a Tree-sitter AST dict to a PyTorch Geometric Data object.

    Parameters
    ----------
    ast_json : dict
        A Tree-sitter AST serialised as nested dicts with keys:
        'type', 'start', 'end', 'text', 'children'.
    label : int | None
        Graph-level label (0=safe, 1=vulnerable). None for inference.

    Returns
    -------
    torch_geometric.data.Data with x, edge_index, y (if label given).
    """
    try:
        import torch
        from torch_geometric.data import Data
    except ImportError:
        raise RuntimeError("pip install torch torch-geometric")

    nodes:      list[list[float]] = []
    edge_src:   list[int]         = []
    edge_dst:   list[int]         = []

    def _walk(node: dict, parent_idx: int, depth: int) -> int:
        """BFS/DFS walk; returns the index assigned to this node."""
        if len(nodes) >= MAX_AST_NODES:
            return len(nodes) - 1

        idx = len(nodes)

        ntype   = node.get("type", "")
        type_id = NODE_TYPE_TO_IDX.get(ntype, UNKNOWN_IDX)

        # One-hot of node type
        feat = [0.0] * VOCAB_SIZE
        feat[type_id] = 1.0

        # Depth (normalised to MAX_DEPTH=20)
        depth_norm = min(depth / 20.0, 1.0)
        feat.append(depth_norm)

        # Is this a call node?
        feat.append(1.0 if ntype in CALL_NODE_TYPES else 0.0)

        nodes.append(feat)

        if parent_idx >= 0:
            # Bidirectional edges for GCN (parent→child + child→parent)
            edge_src.extend([parent_idx, idx])
            edge_dst.extend([idx, parent_idx])

        for child in node.get("children", []):
            _walk(child, idx, depth + 1)

        return idx

    _walk(ast_json, -1, 0)

    x = torch.tensor(nodes, dtype=torch.float)

    if edge_src:
        edge_index = torch.tensor([edge_src, edge_dst], dtype=torch.long)
    else:
        edge_index = torch.zeros((2, 0), dtype=torch.long)

    data = Data(x=x, edge_index=edge_index)
    if label is not None:
        data.y = torch.tensor([label], dtype=torch.long)

    return data


# ─── GCN Model ───────────────────────────────────────────────────────────────

def _build_gcn_model(in_dim: int, hidden: int = GNN_HIDDEN, dropout: float = GNN_DROPOUT):
    """Build 3-layer GCN with global mean pooling and 2-class head."""
    try:
        import torch
        import torch.nn as nn
        from torch_geometric.nn import GCNConv, global_mean_pool
    except ImportError:
        raise RuntimeError("pip install torch torch-geometric")

    class VulnGCN(nn.Module):
        def __init__(self):
            super().__init__()
            self.conv1   = GCNConv(in_dim,  hidden)
            self.conv2   = GCNConv(hidden,  hidden)
            self.conv3   = GCNConv(hidden,  hidden)
            self.dropout = nn.Dropout(p=dropout)
            self.relu    = nn.ReLU()
            self.head    = nn.Linear(hidden, 2)

        def forward(self, x, edge_index, batch):
            h = self.relu(self.conv1(x, edge_index))
            h = self.dropout(h)
            h = self.relu(self.conv2(h, edge_index))
            h = self.dropout(h)
            h = self.relu(self.conv3(h, edge_index))
            # Global mean pooling → graph-level embedding
            g = global_mean_pool(h, batch)
            return self.head(g)

    return VulnGCN()


# ─── Dataset helpers ─────────────────────────────────────────────────────────

def _build_graph_dataset_from_raw(codes: list[str], labels: list[int]) -> list:
    """
    Convert raw code snippets to lightweight graph-like Data objects.
    Uses a simplified token-graph (no Tree-sitter needed at this stage)
    when no AST is available — creates a chain graph over tokens.
    """
    try:
        import torch
        from torch_geometric.data import Data
    except ImportError:
        raise RuntimeError("pip install torch torch-geometric")

    dataset = []
    for code, lbl in zip(codes, labels):
        tokens = code.split()[:MAX_AST_NODES]
        n = max(len(tokens), 1)

        # Node features: token index (mod VOCAB_SIZE) + depth 0 + is_call
        x_rows = []
        for i, tok in enumerate(tokens):
            feat = [0.0] * VOCAB_SIZE
            h    = hash(tok) % VOCAB_SIZE
            feat[h] = 1.0
            feat.append(0.0)   # depth
            feat.append(1.0 if tok.endswith("(") else 0.0)
            x_rows.append(feat)

        x = torch.tensor(x_rows, dtype=torch.float)

        # Chain graph: i → i+1 (bidirectional)
        if n > 1:
            src = list(range(n - 1)) + list(range(1, n))
            dst = list(range(1, n)) + list(range(n - 1))
            edge_index = torch.tensor([src, dst], dtype=torch.long)
        else:
            edge_index = torch.zeros((2, 0), dtype=torch.long)

        data = Data(x=x, edge_index=edge_index,
                    y=torch.tensor([lbl], dtype=torch.long))
        dataset.append(data)

    return dataset


# ─── Training loop ────────────────────────────────────────────────────────────

def train_gnn(
    dataset_result,
    output_path: str = DEFAULT_OUT_PATH,
    epochs: int = GNN_EPOCHS,
    lr: float = GNN_LR,
    batch_size: int = GNN_BATCH,
    hidden: int = GNN_HIDDEN,
    dropout: float = GNN_DROPOUT,
) -> "GNNPredictor":
    """
    Train a 3-layer GCN on the provided DatasetResult.

    Parameters
    ----------
    dataset_result : DatasetResult
        From ml.dataset_loader.load_all_datasets(); uses raw_train/raw_test.
    output_path : str
        Path to save the trained model weights (.pt).
    epochs, lr, batch_size, hidden, dropout : hyperparameters.

    Returns
    -------
    GNNPredictor ready for inference.
    """
    try:
        import torch
        from torch_geometric.data import DataLoader as GeoLoader
    except ImportError:
        raise RuntimeError("pip install torch torch-geometric")

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    device = "cuda" if torch.cuda.is_available() else "cpu"
    log.info(f"GNN training on {device}")

    # ── Build graph datasets ──────────────────────────────────────────────────
    log.info("Building train graphs…")
    train_graphs = _build_graph_dataset_from_raw(
        dataset_result.raw_train, dataset_result.y_train.tolist()
    )
    log.info("Building test graphs…")
    test_graphs  = _build_graph_dataset_from_raw(
        dataset_result.raw_test, dataset_result.y_test.tolist()
    )

    train_loader = GeoLoader(train_graphs, batch_size=batch_size, shuffle=True,
                             num_workers=0)
    test_loader  = GeoLoader(test_graphs,  batch_size=batch_size, shuffle=False,
                             num_workers=0)

    # ── Model, optimiser, loss ────────────────────────────────────────────────
    model = _build_gcn_model(NODE_FEAT_DIM, hidden, dropout).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.StepLR(optimizer, step_size=10, gamma=0.5)

    # Weighted cross-entropy for class imbalance
    y_tr = np.array(dataset_result.y_train)
    n_pos = max(1, int(y_tr.sum()))
    n_neg = max(1, int((y_tr == 0).sum()))
    weight = torch.tensor([1.0, n_neg / n_pos], dtype=torch.float).to(device)
    criterion = torch.nn.CrossEntropyLoss(weight=weight)

    # ── Training loop ─────────────────────────────────────────────────────────
    best_acc   = 0.0
    best_state = None

    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        for batch in train_loader:
            batch = batch.to(device)
            optimizer.zero_grad()
            out_logits = model(batch.x, batch.edge_index, batch.batch)
            loss       = criterion(out_logits, batch.y.view(-1))
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            total_loss += float(loss.item())

        scheduler.step()

        # Eval
        model.eval()
        correct = total = 0
        with torch.no_grad():
            for batch in test_loader:
                batch  = batch.to(device)
                logits = model(batch.x, batch.edge_index, batch.batch)
                preds  = logits.argmax(dim=1)
                correct += int((preds == batch.y.view(-1)).sum())
                total   += batch.y.size(0)

        acc = correct / max(total, 1)
        log.info(f"Epoch {epoch:3d}/{epochs}  loss={total_loss/len(train_loader):.4f}  "
                 f"val_acc={acc:.4f}")

        if acc > best_acc:
            best_acc   = acc
            best_state = {k: v.cpu().clone() for k, v in model.state_dict().items()}

    # ── Save best weights ─────────────────────────────────────────────────────
    if best_state is not None:
        model.load_state_dict(best_state)

    torch.save({
        "model_state_dict": model.state_dict(),
        "hidden":  hidden,
        "dropout": dropout,
        "in_dim":  NODE_FEAT_DIM,
        "best_acc": best_acc,
    }, str(out))
    log.info(f"GNN saved to {out}  best_acc={best_acc:.4f}")

    return GNNPredictor(model=model, device=device)


# ─── Inference wrapper ────────────────────────────────────────────────────────

class GNNPredictor:
    """
    Inference wrapper for the trained GCN model.

    Accepts either:
      - A Tree-sitter AST dict  (ast_to_data() path)
      - Raw source code string  (token-chain fallback)
    """

    def __init__(self, model=None, device: Optional[str] = None):
        self._model  = model
        self._device = device or ("cuda" if self._cuda_available() else "cpu")
        if self._model is not None:
            self._model.to(self._device)
            self._model.eval()

    @staticmethod
    def _cuda_available() -> bool:
        try:
            import torch; return torch.cuda.is_available()
        except ImportError:
            return False

    @classmethod
    def load(cls, path: str = DEFAULT_OUT_PATH) -> "GNNPredictor":
        """Load a previously saved GNN checkpoint."""
        try:
            import torch
        except ImportError:
            raise RuntimeError("pip install torch torch-geometric")

        ckpt   = torch.load(path, map_location="cpu")
        hidden  = ckpt.get("hidden",  GNN_HIDDEN)
        dropout = ckpt.get("dropout", GNN_DROPOUT)
        in_dim  = ckpt.get("in_dim",  NODE_FEAT_DIM)

        model = _build_gcn_model(in_dim, hidden, dropout)
        model.load_state_dict(ckpt["model_state_dict"])
        log.info(f"Loaded GNN from {path} (best_acc={ckpt.get('best_acc', '?')})")
        return cls(model=model)

    def predict(self, source: dict | str) -> float:
        """
        Predict vulnerability probability.

        Parameters
        ----------
        source : dict | str
            Either a Tree-sitter AST dict or a raw source code string.

        Returns
        -------
        float in [0.0, 1.0].
        """
        try:
            import torch
            from torch_geometric.data import Batch
        except ImportError:
            raise RuntimeError("pip install torch torch-geometric")

        if self._model is None:
            raise RuntimeError("Model not loaded.")

        if isinstance(source, dict):
            data = ast_to_data(source)
        else:
            graphs = _build_graph_dataset_from_raw([source], [0])
            data   = graphs[0]

        batch  = Batch.from_data_list([data]).to(self._device)
        with torch.no_grad():
            logits = self._model(batch.x, batch.edge_index, batch.batch)
            proba  = torch.softmax(logits, dim=-1)
        return float(proba[0, 1].cpu().item())

    @property
    def is_loaded(self) -> bool:
        return self._model is not None


# ─── CLI training entrypoint ──────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    from ml.dataset_loader import load_all_datasets

    dataset = load_all_datasets(max_per_dataset=2000)
    print(dataset)

    predictor = train_gnn(dataset, output_path=DEFAULT_OUT_PATH, epochs=10)
    print("Sample predict:", predictor.predict("int* p = malloc(10); free(p); p[0]=1;"))
