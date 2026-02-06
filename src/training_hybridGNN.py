import os
import json
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
from torch_geometric.data import Data
# 1. DEPRECATION FIX: Import DataLoader from 'loader'
from torch_geometric.loader import DataLoader
from torch_geometric.nn import GCNConv, GATConv, TransformerConv, global_mean_pool, global_max_pool
from torch_geometric.nn import GraphNorm  
from sklearn.model_selection import KFold
from sklearn.metrics import f1_score, accuracy_score
import pandas as pd
from typing import List, Dict, Any

# =============================================================================
# 1. COMPREHENSIVE PDV FEATURE EXTRACTION (Unchanged)
# =============================================================================
def extract_enhanced_pdv_features(json_data: Dict[str, Any]) -> List[float]:
    """
    Extracts the flattened feature vector from unified_pdv.
    UPDATED: Matches the new scientifically rigorous 27-feature PDV.
    """
    unified_pdv = json_data.get("unified_pdv", {})
    
    # EXACT MATCH with UnifiedPDVProcessor.feature_names
    # This ensures the order is deterministic and matches the generated data.
    pdv_feature_keys = [
        # 1. Core Parameters
        'block_size', 'key_size', 'rounds',
        
        # 2. Family Indicators
        'is_feistel', 'is_arx', 'is_spn', 'is_hybrid',
        
        # 3. Structural Topology
        'branch_count', 
        'sbox_type', 
        'permutation_type',
        
        # 4. Operation Counts
        'xor_count', 'rotl_count', 'rotr_count', 
        'add_count', 'sub_count', 'and_count', 
        'sbox_count', 'perm_count',
        
        # 5. Densities
        'nonlinearity_density', 
        'diffusion_density', 
        'state_update_density',
        
        # 6. Graph Statistics
        'ast_node_count', 'ast_edge_count', 'function_count',
        'cyclomatic_complexity_proxy',
        
        # 7. Key Schedule
        'key_schedule_type', 
        'key_injection_type',
    
        'algebraic_degree_proxy',
        'key_state_ratio',
        'sbox_density',
        'avg_degree_centrality',
        'critical_path_proxy',
        'interaction_density',
    ]
    
    all_features = []
    for key in pdv_feature_keys:
        # Get value, default to 0.0 if missing
        value = unified_pdv.get(key, 0.0)
        
        # New Processor ensures values are numbers, but safety check is good
        try:
            val_float = float(value)
        except (ValueError, TypeError):
            val_float = 0.0
            
        all_features.append(val_float)

    
    return all_features

# =============================================================================
# 2. ROBUST GRAPH DATA ENCODER (Unchanged)
# =============================================================================
class GraphDataEncoder:
    """
    V2: This version now correctly parses the 'cryptographic_patterns'
    dictionary from 'function' nodes and adds them to the feature vector.
    """
    def __init__(self):
        # Categorical feature mappings
        self.type_map = {}
        self.role_map = {}
        self.flow_role_map = {}
        self.context_map = {}
        self.edge_type_map = {}
        
        # Numerical feature counts
        self.base_numerical_features = 3  # strength, diffusion, nonlinearity
        
        # ## NEW: Define the number of features we will extract from function patterns ##
        # This will be 10 features, see _encode_node for details
        self.function_pattern_features = 10 
        
        # Final dimensions
        self.node_feat_dim = 0
        self.pdv_feat_dim = 0
        self.edge_attr_dim = 1

    def _build_mapping(self, items: List[str], unknown_key="unknown") -> Dict[str, int]:
        unique_items = sorted(list(set(items)))
        mapping = {item: i for i, item in enumerate(unique_items)}
        if unknown_key not in mapping:
            mapping[unknown_key] = len(mapping)
        return mapping

    def _one_hot(self, key: str, mapping: Dict[str, int], unknown_key="unknown") -> List[float]:
        vec = [0.0] * len(mapping)
        idx = mapping.get(key, mapping.get(unknown_key))
        if idx is not None:
            vec[idx] = 1.0
        return vec

    def fit(self, all_json_data: List[Dict[str, Any]]):
        """
        Fits the encoder by scanning all JSON files to build
        complete categorical feature mappings.
        """
        print("Fitting encoder on dataset...")
        all_types, all_roles, all_flow_roles, all_contexts, all_edge_types = [], [], [], [], []

        for js in all_json_data:
            for node in js.get("nodes", []):
                all_types.append(node.get("type", "unknown"))
                all_roles.append(node.get("crypto_role", "unknown"))
                all_flow_roles.append(node.get("data_flow_role", "unknown"))
                all_contexts.append(node.get("context", "unknown"))
            for edge in js.get("edges", []):
                all_edge_types.append(edge.get("type", "unknown"))

        # Build mappings
        self.type_map = self._build_mapping(all_types)
        self.role_map = self._build_mapping(all_roles)
        self.flow_role_map = self._build_mapping(all_flow_roles)
        self.context_map = self._build_mapping(all_contexts)
        self.edge_type_map = self._build_mapping(all_edge_types)

        # Calculate categorical dimension
        categorical_dim = (
            len(self.type_map) +
            len(self.role_map) +
            len(self.flow_role_map) +
            len(self.context_map)
        )
        
        # Calculate TOTAL node dimension
        self.node_feat_dim = (
            self.base_numerical_features +
            self.function_pattern_features +  
            categorical_dim
        )
        
        # Get PDV dim
        if all_json_data:
            self.pdv_feat_dim = len(extract_enhanced_pdv_features(all_json_data[0]))
        
        print(f"✅ Encoder fit complete.")
        print(f"  > Base Numerical Dims:     {self.base_numerical_features}")
        print(f"  > Function Pattern Dims:   {self.function_pattern_features}")
        print(f"  > Categorical Dims:      {categorical_dim} (from {len(self.type_map)} types, {len(self.role_map)} roles, etc.)")
        print(f"  > TOTAL NODE FEAT DIM: {self.node_feat_dim}")
        print(f"  > PDV feat dim:            {self.pdv_feat_dim}")
        print(f"  > Edge types:              {len(self.edge_type_map)}")


    def _encode_node(self, node: Dict[str, Any]) -> List[float]:
        """
        Encodes a single node using the fitted mappings.
        V2: Now includes function pattern features.
        """
        
        # 1. Base Numerical Features (3 Dims)
        numerical_vec = [
            float(node.get("crypto_strength", 0.0)),
            float(node.get("diffusion_power", 0.0)),
            float(node.get("nonlinearity", 0.0))
        ]
        
        # 2. NEW: Function-Specific Numerical Features (10 Dims)
        function_vec = [0.0] * self.function_pattern_features
        if node.get("type") == "function":
            patterns = node.get("cryptographic_patterns", {})
            op_dist = patterns.get("cryptographic_operation_distribution", {})
            
            function_vec = [
                1.0 if patterns.get("feistel_network") else 0.0,
                len(patterns.get("arx_operation_chains", [])),
                1.0 if patterns.get("spn_layers") else 0.0,
                float(patterns.get("key_schedule_complexity", 0.0)),
                float(patterns.get("feistel_rounds_detected", 0.0)),
                len(patterns.get("round_structures", [])),
                float(op_dist.get("linear_mixing", 0.0)),
                float(op_dist.get("nonlinear_mixing", 0.0)),
                float(op_dist.get("diffusion", 0.0)),
                float(op_dist.get("operation", 0.0))
            ]
        
        # 3. Categorical (One-Hot) Features (e.g., 101 Dims)
        type_vec = self._one_hot(node.get("type", "unknown"), self.type_map)
        role_vec = self._one_hot(node.get("crypto_role", "unknown"), self.role_map)
        flow_vec = self._one_hot(node.get("data_flow_role", "unknown"), self.flow_role_map)
        context_vec = self._one_hot(node.get("context", "unknown"), self.context_map)
        
        # Concatenate all features into a single, fixed-size vector
        features = (
            numerical_vec +
            function_vec +
            type_vec + 
            role_vec + 
            flow_vec + 
            context_vec
        )
        
        return features

    def transform(self, js: Dict[str, Any]) -> Data:
        """
        Transforms a single JSON object into a PyG Data object.
        """
        
        # --- PDV Features ---
        pdv_features = extract_enhanced_pdv_features(js)
        if self.pdv_feat_dim > 0 and len(pdv_features) != self.pdv_feat_dim:
            raise ValueError(f"PDV feature dimension mismatch for {js.get('cipher_variant')}")
        pdv = torch.tensor([pdv_features], dtype=torch.float)

        # --- Node Features ---
        nodes_data = js.get("nodes", [])
        if not nodes_data:
            dummy_node = {"type": "unknown", "crypto_role": "unknown", "data_flow_role": "unknown", "context": "unknown"}
            node_feats = [self._encode_node(dummy_node)]
            nodes_data = [dummy_node]
        else:
            node_feats = [self._encode_node(node) for node in nodes_data]
            
        x = torch.tensor(node_feats, dtype=torch.float)
        
        # --- Sanity Check ---
        if x.shape[1] != self.node_feat_dim:
            # This should not happen if .fit() was called, but it's a good safeguard
            raise RuntimeError(f"Feature dimension mismatch! Encoder.dim={self.node_feat_dim} but created vector of size={x.shape[1]}")

        # --- Edge Index (CRITICAL FIX) ---
        id_to_index = {node['id']: i for i, node in enumerate(nodes_data) if 'id' in node}
        edges = js.get("edges", [])
        edge_sources, edge_targets, edge_attrs = [], [], []
        
        for e in edges:
            source_id, target_id = e.get("source"), e.get("target")
            edge_type = e.get("type", "unknown")
            
            if source_id in id_to_index and target_id in id_to_index:
                edge_sources.append(id_to_index[source_id])
                edge_targets.append(id_to_index[target_id])
                edge_type_idx = self.edge_type_map.get(edge_type, self.edge_type_map.get("unknown", 0))
                edge_attrs.append([float(edge_type_idx)])
        
        if edge_sources:
            edge_index = torch.tensor([edge_sources, edge_targets], dtype=torch.long)
            edge_attr = torch.tensor(edge_attrs, dtype=torch.float)
        else:
            edge_index = torch.tensor([[], []], dtype=torch.long)
            edge_attr = torch.empty((0, self.edge_attr_dim), dtype=torch.float)

        # --- Label ---
        # UPDATED FOR 4 CLASSES
        #label_map = {"low": 0, "medium": 1, "high": 2}
        label_map = {"broken": 0, "low": 1, "medium": 2, "high": 3}
        security_label = js.get("security_label", "low")
        y = torch.tensor([label_map.get(security_label, 1)], dtype=torch.long) # Default to 1 (Low) if unknown
        
        
        
        # --- Create Data Object ---
        data = Data(x=x, edge_index=edge_index, edge_attr=edge_attr, y=y, pdv=pdv)
        data.cipher = js.get("cipher_variant", "unknown")
        data.filename = js.get("source_file", "unknown")
        
        return data

# =============================================================================
# 3. UPDATED DATA LOADING PIPELINE (Unchanged)
# =============================================================================

def load_all_json_data(sampled_data_dir: str) -> List[Dict[str, Any]]:
    """First pass: Load all JSON data from subdirectories into memory."""
    all_json_data = []
    print(f"Scanning for JSON files in {sampled_data_dir}...")
    for cipher_dir in os.listdir(sampled_data_dir):
        cipher_path = os.path.join(sampled_data_dir, cipher_dir)
        if not os.path.isdir(cipher_path):
            continue
            
        json_files = [os.path.join(cipher_path, f) for f in os.listdir(cipher_path) 
                      if f.endswith(".json") and not f.startswith('_')]
        
        for f in json_files:
            try:
                with open(f, "r") as jf:
                    js = json.load(jf)
                if isinstance(js, list) or "nodes" not in js or "unified_pdv" not in js:
                    print(f"⚠️ Skipping {f}: Incomplete or old format.")
                    continue
                js['source_file_path'] = f
                all_json_data.append(js)
            except Exception as e:
                print(f"⚠️ Error reading {f}: {e}")
                
    print(f"Found {len(all_json_data)} valid JSON files.")
    return all_json_data


def load_enhanced_graphs_from_dataset(sampled_data_dir: str):
    """
    Loads all graphs and returns the processed Data objects and the fitted encoder.
    """
    all_json_data = load_all_json_data(sampled_data_dir)
    if not all_json_data:
        raise ValueError("No valid JSON data found in directory.")

    encoder = GraphDataEncoder()
    encoder.fit(all_json_data)
    
    graphs = []
    for js in all_json_data:
        try:
            data = encoder.transform(js)
            graphs.append(data)
        except Exception as e:
            print(f"⚠️ Error transforming {js.get('source_file_path')}: {e}")

    print(f"✅ Loaded {len(graphs)} graphs with enhanced features.")
    
    # !!! ADD THIS LINE from your last request !!!
    print(f"📊 Label Distribution (0=broken, 1=low, 2=medium, 3=high): {np.bincount([d.y.item() for d in graphs])}")
    
    return graphs, encoder


## MODIFIED ##
def prepare_test_cipher_enhanced(json_file_path: str, encoder: GraphDataEncoder) -> Dict:
    """
    Loads and transforms a single, unseen cipher (like HIGHT)
    using the *already-fitted* encoder.
    """
    print(f"\nPreparing unseen test cipher: {json_file_path}")
    try:
        with open(json_file_path, "r") as jf:
            js = json.load(jf)

        # ## MODIFIED: Check if the test file has a label ##
        if "security_label" not in js:
            print(f"⚠️ Test file {json_file_path} has no 'security_label'. Cannot check correctness.")
            true_label_str = "unknown"
        else:
            true_label_str = js.get("security_label")
            
        data = encoder.transform(js)
        test_loader = DataLoader([data], batch_size=1)
        batched_data = next(iter(test_loader))
        
        #label_map = {"low": 0, "medium": 1, "high": 2, "unknown": -1}
        label_map = {"broken": 0, "low": 1, "medium": 2, "high": 3, "unknown": -1}
        label_names = {v: k for k, v in label_map.items()}
        
        return {
            'gnn_data': batched_data,
            'true_label': label_map.get(true_label_str), 
            'label_names': label_names,
            'cipher_name': os.path.basename(json_file_path).replace('.json', '')
        }
    except Exception as e:
        print(f"❌ Error preparing test cipher {json_file_path}: {e}")
        return None
        
# =============================================================================
# 4. HYBRID MODEL ARCHITECTURES (Dynamic Layers - Unchanged)
# =============================================================================
def _build_mlp(in_dim: int, hidden_dims: List[int], dropout: float, use_batchnorm: bool = False) -> nn.Sequential:
    """
    Helper function to build a dynamic MLP.
    UPDATED: Now supports Batch Normalization to stabilize training with raw count features.
    """
    layers = nn.ModuleList()
    for dim in hidden_dims:
        layers.append(nn.Linear(in_dim, dim))
        if use_batchnorm:
            layers.append(nn.BatchNorm1d(dim))
        layers.append(nn.ReLU())
        layers.append(nn.Dropout(dropout))
        in_dim = dim
    return nn.Sequential(*layers)
    
# def _build_mlp(in_dim: int, hidden_dims: List[int], dropout: float) -> nn.Sequential:
#     """Helper function to build a dynamic MLP."""
#     layers = nn.ModuleList()
#     for dim in hidden_dims:
#         layers.append(nn.Linear(in_dim, dim))
#         layers.append(nn.ReLU())
#         layers.append(nn.Dropout(dropout))
#         in_dim = dim
#     return nn.Sequential(*layers)

class FocusedGCNModel(nn.Module):
    def __init__(self, node_feat_dim, pdv_dim, n_classes, config):
        super().__init__()
        self.config = config
        
        # Build Dynamic GNN
        self.convs = nn.ModuleList()
        self.norms = nn.ModuleList() # GraphNorm per layer
        
        in_dim = node_feat_dim
        for out_dim in config['gcn_dims']:
            self.convs.append(GCNConv(in_dim, out_dim))
            self.norms.append(GraphNorm(out_dim)) 
            in_dim = out_dim
            
        self.gnn_out_dim = config['gcn_dims'][-1]
        
        # Build Dynamic PDV MLP
        # use_batchnorm=True to handle raw counts/densities
        self.pdv_mlp = _build_mlp(pdv_dim, config['pdv_dims'], config['dropout'], use_batchnorm=True)
        self.pdv_out_dim = config['pdv_dims'][-1] if config['pdv_dims'] else pdv_dim

        # Classifier
        # Input dim is doubled because we concatenate Mean + Max pooling
        combined_in_dim = (self.gnn_out_dim * 2) + self.pdv_out_dim 
        
        #  Classifier also uses BatchNorm for stability
        self.classifier = _build_mlp(combined_in_dim, config['classifier_dims'], config['dropout'], use_batchnorm=True)
        classifier_in_dim = config['classifier_dims'][-1] if config['classifier_dims'] else combined_in_dim
        self.classifier.add_module("output_layer", nn.Linear(classifier_in_dim, n_classes))

    def forward(self, data):
        x, edge_index, batch = data.x, data.edge_index, data.batch
        
        for i, conv in enumerate(self.convs):
            x = conv(x, edge_index)
            x = self.norms[i](x, batch) 
            
            if i < len(self.convs) - 1:
                x = F.relu(x)
                x = F.dropout(x, p=self.config['dropout'], training=self.training)
        
        # Global Pooling Strategy (Mean + Max)
        x_mean = global_mean_pool(x, batch)
        x_max = global_max_pool(x, batch)
        ast_out = torch.cat([x_mean, x_max], dim=1)
        
        # PDV Path
        # Ensure input is float for BatchNorm
        pdv_out = self.pdv_mlp(data.pdv.view(-1, data.pdv.shape[-1]).float())
            
        # Combine
        combined = torch.cat([ast_out, pdv_out], dim=1)
        return self.classifier(combined)

        
class FocusedGATModel(nn.Module):
    def __init__(self, node_feat_dim, pdv_dim, n_classes, config):
        super().__init__()
        self.config = config
        heads = config['heads']
        
        # Build Dynamic GNN
        self.convs = nn.ModuleList()
        self.norms = nn.ModuleList()
        
        in_dim = node_feat_dim
        for i, out_dim in enumerate(config['gat_dims']):
            # For GAT, we assume intermediate layers concat heads, last layer averages (or concats based on design)
            # Here we follow PyG convention or simple concat for feature preservation
            self.convs.append(GATConv(in_dim, out_dim, heads=heads, concat=True))
            
            # Output of GAT with concat=True is out_dim * heads
            actual_out_dim = out_dim * heads
            self.norms.append(GraphNorm(actual_out_dim))
            
            in_dim = actual_out_dim
            
        self.gnn_out_dim = in_dim
        
        # Build Dynamic PDV MLP (With BatchNorm)
        self.pdv_mlp = _build_mlp(pdv_dim, config['pdv_dims'], config['dropout'], use_batchnorm=True)
        self.pdv_out_dim = config['pdv_dims'][-1] if config['pdv_dims'] else pdv_dim

        # Classifier
        combined_in_dim = (self.gnn_out_dim * 2) + self.pdv_out_dim 
        
        self.classifier = _build_mlp(combined_in_dim, config['classifier_dims'], config['dropout'], use_batchnorm=True)
        classifier_in_dim = config['classifier_dims'][-1] if config['classifier_dims'] else combined_in_dim
        self.classifier.add_module("output_layer", nn.Linear(classifier_in_dim, n_classes))

    def forward(self, data):
        x, edge_index, batch = data.x, data.edge_index, data.batch
        
        for i, conv in enumerate(self.convs):
            x = conv(x, edge_index)
            x = self.norms[i](x, batch)
            
            if i < len(self.convs) - 1:
                x = F.elu(x)
                x = F.dropout(x, p=self.config['dropout'], training=self.training)
        
        x_mean = global_mean_pool(x, batch)
        x_max = global_max_pool(x, batch)
        ast_out = torch.cat([x_mean, x_max], dim=1)
        
        # PDV Path
        pdv_out = self.pdv_mlp(data.pdv.view(-1, data.pdv.shape[-1]).float())
            
        combined = torch.cat([ast_out, pdv_out], dim=1)
        return self.classifier(combined)


class FocusedTransformerModel(nn.Module):
    def __init__(self, node_feat_dim, pdv_dim, edge_attr_dim, n_classes, config):
        super().__init__()
        self.config = config
        heads = config['heads']

        # Build Dynamic GNN
        self.convs = nn.ModuleList()
        self.norms = nn.ModuleList()
        
        in_dim = node_feat_dim
        for i, out_dim in enumerate(config['transformer_dims']):
            is_last_layer = (i == len(config['transformer_dims']) - 1)
            
            if is_last_layer:
                layer_heads = 1
                concat = False
            else:
                layer_heads = heads
                concat = True
                
            self.convs.append(TransformerConv(in_dim, out_dim, heads=layer_heads, 
                                              concat=concat, edge_dim=edge_attr_dim))
            
            actual_out_dim = out_dim * layer_heads if concat else out_dim
            self.norms.append(GraphNorm(actual_out_dim))
            
            in_dim = actual_out_dim
            
        self.gnn_out_dim = in_dim

        # Build Dynamic PDV MLP (With BatchNorm)
        self.pdv_mlp = _build_mlp(pdv_dim, config['pdv_dims'], config['dropout'], use_batchnorm=True)
        self.pdv_out_dim = config['pdv_dims'][-1] if config['pdv_dims'] else pdv_dim

        # Classifier
        combined_in_dim = (self.gnn_out_dim * 2) + self.pdv_out_dim 
        
        self.classifier = _build_mlp(combined_in_dim, config['classifier_dims'], config['dropout'], use_batchnorm=True)
        classifier_in_dim = config['classifier_dims'][-1] if config['classifier_dims'] else combined_in_dim
        self.classifier.add_module("output_layer", nn.Linear(classifier_in_dim, n_classes))

    def forward(self, data):
        x, edge_index, batch = data.x, data.edge_index, data.batch
        
        for i, conv in enumerate(self.convs):
            x = conv(x, edge_index, data.edge_attr)
            x = self.norms[i](x, batch)
            
            if i < len(self.convs) - 1:
                x = F.elu(x)
                x = F.dropout(x, p=self.config['dropout'], training=self.training)
        
        x_mean = global_mean_pool(x, batch)
        x_max = global_max_pool(x, batch)
        ast_out = torch.cat([x_mean, x_max], dim=1)
        
        # PDV Path
        pdv_out = self.pdv_mlp(data.pdv.view(-1, data.pdv.shape[-1]).float())
            
        combined = torch.cat([ast_out, pdv_out], dim=1)
        return self.classifier(combined)

        
# =============================================================================
# 5. FOCUSED GRID TRAINING MANAGER (MODIFIED)
# =============================================================================

class FocusedGridTrainingManager:
    ## MODIFIED: Changed constructor to take a directory
    def __init__(self, base_data_dir="sampled_data_variant_based_balanced_V6", 
                 test_ciphers_dir="test_only_ciphers"):
        self.base_data_dir = base_data_dir
        self.test_ciphers_dir = test_ciphers_dir # <-- MODIFIED
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.results = {}
        self.encoder = None 
        print(f"Using device: {self.device}")

    def get_model(self, model_type, node_feat_dim, pdv_dim, edge_attr_dim, n_classes, config):
        if model_type == 'GCN':
            return FocusedGCNModel(node_feat_dim, pdv_dim, n_classes, config)
        elif model_type == 'GAT':
            return FocusedGATModel(node_feat_dim, pdv_dim, n_classes, config)
        elif model_type == 'Transformer':
            return FocusedTransformerModel(node_feat_dim, pdv_dim, edge_attr_dim, n_classes, config)
        else:
            raise ValueError(f"Unknown model type: {model_type}")

    ## MODIFIED: Added 3-fold split for n_samples < 50
    def get_training_config(self, n_samples, model_config):
        """Get training configuration optimized for dataset size"""
        
        if n_samples < 50:  # dataset-3 (45 samples)
            batch_size = max(4, n_samples // 8)
            n_splits = 3  # Use 3 folds for a more stable validation set (15 samples)
        elif n_samples < 80:  # dataset sizes 4-5
            batch_size = max(8, n_samples // 8)
            n_splits = 5
        else:  # dataset sizes 6-8
            batch_size = max(12, n_samples // 10)
            n_splits = 5
        
        return {
            'batch_size': batch_size,
            'n_epochs': model_config['n_epochs'], 
            'patience': model_config['patience'],
            'lr': model_config['lr'],
            'weight_decay': model_config['weight_decay'],
            'n_splits': n_splits
        }

    def train_single_fold(self, model, train_loader, val_loader, config):
        model = model.to(self.device)
        criterion = nn.CrossEntropyLoss()
        optimizer = torch.optim.AdamW(
            model.parameters(), 
            lr=config['lr'], 
            weight_decay=config['weight_decay']
        )
        
        # 2. DEPRECATION FIX: Removed 'verbose=False'
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            optimizer, patience=config['patience']//3, factor=0.5
        )
        
        best_val_f1 = -1.0
        patience_counter = 0
        best_state = None
        
        for epoch in range(config['n_epochs']):
            model.train()
            epoch_loss = 0
            for batch in train_loader:
                batch = batch.to(self.device)
                optimizer.zero_grad()
                out = model(batch)
                loss = criterion(out, batch.y)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                optimizer.step()
                epoch_loss += loss.item()
            
            val_f1, _ = self.evaluate_model(model, val_loader)
            scheduler.step(epoch_loss / len(train_loader))
            
            if val_f1 > best_val_f1:
                best_val_f1 = val_f1
                patience_counter = 0
                best_state = model.state_dict().copy()
            else:
                patience_counter += 1
            
            if patience_counter >= config['patience']:
                break
        
        if best_state is not None:
            model.load_state_dict(best_state)
        
        return best_val_f1, model

    def evaluate_model(self, model, loader):
        model.eval()
        y_true, y_pred = [], []
        with torch.no_grad():
            for batch in loader:
                batch = batch.to(self.device)
                out = model(batch)
                pred = out.argmax(dim=1)
                y_true.extend(batch.y.cpu().tolist())
                y_pred.extend(pred.cpu().tolist())
        
        f1 = f1_score(y_true, y_pred, average="macro", zero_division=0.0)
        acc = accuracy_score(y_true, y_pred)
        return f1, acc

    ## MODIFIED: Renamed function and added loop ##
    def test_on_unseen_ciphers(self, model, encoder):
        """Test trained model on all ciphers in the test directory"""
        
        test_results = {}
        
        if not os.path.exists(self.test_ciphers_dir):
            print(f"❌ Test directory not found: {self.test_ciphers_dir}")
            return None

        test_files = [f for f in os.listdir(self.test_ciphers_dir) if f.endswith('.json')]
        if not test_files:
            print(f"⚠️ No .json files found in {self.test_ciphers_dir}")
            return None
            
        print(f"  🎯 TESTING ON {len(test_files)} UNSEEN CIPHERS:")
        
        for test_file in test_files:
            file_path = os.path.join(self.test_ciphers_dir, test_file)
            test_data_package = prepare_test_cipher_enhanced(file_path, encoder)
            
            if test_data_package is None:
                continue
                
            test_data = test_data_package['gnn_data'].to(self.device)
            true_label = test_data_package['true_label']
            label_names = test_data_package['label_names']
            cipher_name = test_data_package['cipher_name']

            try:
                model.eval()
                with torch.no_grad():
                    output = model(test_data)
                    probabilities = F.softmax(output, dim=1)
                    prediction = output.argmax(dim=1).cpu().item()
                    confidence = probabilities.max().cpu().item()
                    confidence_per_class = probabilities.cpu().numpy()[0]
                
                correct = (prediction == true_label) 
                
                result_key = f"test_{cipher_name}"
                test_results[result_key] = {
                    'prediction': prediction,
                    'prediction_label': label_names[prediction],
                    'confidence': confidence,
                    'confidence_broken': confidence_per_class[0],
                    'confidence_low': confidence_per_class[1],
                    'confidence_medium': confidence_per_class[2],
                    'confidence_high': confidence_per_class[3],
                    'correct': bool(correct)
                }
                
                status = "✅ CORRECT" if correct else "❌ WRONG"
                if true_label == -1: status = "?? UNKNOWN"
                print(f"     {cipher_name:20}: Pred={label_names[prediction]:<7} - {status}")
                print(test_results[result_key])

            except Exception as e:
                print(f"❌ {cipher_name} test failed: {e}")
                print(test_results[result_key])
                
                
        return test_results

    ## MODIFIED: Updated to handle the new test results dictionary ##
    def run_focused_grid_training(self, dataset_sizes=None, model_types=None):
        if dataset_sizes is None:
            dataset_sizes = [8, 15, 30]
        if model_types is None:
            model_types = ['GCN', 'GAT', 'Transformer']
        
        print("🎯 FOCUSED GRID TRAINING (Sweet Spot: Datasets 3-5)")
        print(f"📊 Dataset Sizes: {dataset_sizes}")
        print(f"🤖 Model Types: {model_types}")
        print("=" * 60)
        
        total_configs = len(dataset_sizes) * len(model_types) * 5
        current_config = 0
        
        for dataset_size in dataset_sizes:
            dataset_dir = f"{self.base_data_dir}/samples_per_variant_{dataset_size}"
            
            if not os.path.exists(dataset_dir):
                print(f"❌ Dataset directory not found: {dataset_dir}")
                continue
            
            try:
                graphs, self.encoder = load_enhanced_graphs_from_dataset(dataset_dir)
            except Exception as e:
                print(f"❌ Failed to load dataset {dataset_dir}: {e}")
                continue
                
            if len(graphs) < 10:
                print(f"⚠️ Skipping size {dataset_size}: only {len(graphs)} graphs")
                continue
                
            node_feat_dim = self.encoder.node_feat_dim
            pdv_dim = self.encoder.pdv_feat_dim
            edge_attr_dim = self.encoder.edge_attr_dim
            n_classes = 4
            
            print(f"\n📦 Dataset Size {dataset_size}: {len(graphs)} graphs")
            print(f"📐 Node Dim: {node_feat_dim}, PDV Dim: {pdv_dim}, Edge Dim: {edge_attr_dim}")
            
            for model_type in model_types:
                configs = FOCUSED_GRID_CONFIGS[model_type]
                
                for config_idx, config in enumerate(configs):
                    current_config += 1
                    config_id = f"size{dataset_size}_{model_type}_config{config_idx+1}"
                    
                    print(f"\n🔧 [{current_config}/{total_configs}] Training {config_id}")
                    
                    training_config = self.get_training_config(len(graphs), config)
                    
                    kf = KFold(n_splits=training_config['n_splits'], shuffle=True, random_state=42)
                    cv_f1_scores, cv_acc_scores, fold_models = [], [], []
                    
                    print(f"  📁 CROSS-VALIDATION ({training_config['n_splits']} folds):")
                    
                    for fold, (train_idx, val_idx) in enumerate(kf.split(graphs)):
                        if len(val_idx) < 2: continue
                        
                        train_loader = DataLoader([graphs[i] for i in train_idx], 
                                                  batch_size=training_config['batch_size'], shuffle=True, drop_last=True )
                        val_loader = DataLoader([graphs[i] for i in val_idx], 
                                                batch_size=min(training_config['batch_size'], len(val_idx)))
                        
                        model = self.get_model(model_type, node_feat_dim, pdv_dim, edge_attr_dim, n_classes, config)
                        
                        _, trained_model = self.train_single_fold(
                            model, train_loader, val_loader, training_config
                        )
                        
                        final_f1, final_acc = self.evaluate_model(trained_model, val_loader)
                        
                        cv_f1_scores.append(final_f1)
                        cv_acc_scores.append(final_acc)
                        fold_models.append(trained_model)
                        
                        print(f"    Fold {fold+1}: Val F1 = {final_f1:.4f}, Val Acc = {final_acc:.4f}")
                    
                    if cv_f1_scores:
                        mean_f1, std_f1 = np.mean(cv_f1_scores), np.std(cv_f1_scores)
                        mean_acc, std_acc = np.mean(cv_acc_scores), np.std(cv_acc_scores)
                        
                        print(f"  📈 CROSS-VALIDATION RESULTS:")
                        print(f"     Mean F1: {mean_f1:.4f} ± {std_f1:.4f}")
                        print(f"     Mean Acc: {mean_acc:.4f} ± {std_acc:.4f}")
                        
                        best_fold_idx = np.argmax(cv_f1_scores)
                        best_model = fold_models[best_fold_idx]
                        
                        os.makedirs(f"{OUTPUT_MODELS_SAVED}", exist_ok=True)
                        model_path = f"{OUTPUT_MODELS_SAVED}/{config_id}_best.pt"
                        torch.save({
                            'state_dict': best_model.state_dict(), 'config': config,
                            'mean_f1': mean_f1, 'mean_acc': mean_acc,
                            'dataset_size': dataset_size, 'model_type': model_type,
                            'node_feat_dim': node_feat_dim, 'pdv_dim': pdv_dim,
                            'edge_attr_dim': edge_attr_dim
                        }, model_path)
                        
                        # ## MODIFIED: Call new test function ##
                        test_results_dict = self.test_on_unseen_ciphers(best_model, self.encoder)
                        
                        # Store all results
                        self.results[config_id] = {
                            'dataset_size': dataset_size, 'model_type': model_type,
                            'config_idx': config_idx, 'mean_f1': mean_f1, 'std_f1': std_f1,
                            'mean_acc': mean_acc, 'std_acc': std_acc,
                            'architecture': config, 'n_samples': len(graphs),
                            'node_feat_dim': node_feat_dim, 'pdv_dim': pdv_dim,
                            'unseen_test_results': test_results_dict # <-- MODIFIED
                        }
                    else:
                        print(f"  ❌ {config_id}: No valid folds completed")
            
        print(f"\n🎉 FOCUSED GRID TRAINING COMPLETED!")
        print(f"📊 Trained {len(self.results)} configurations")
        
        return self.results

# =============================================================================
# 6. RESULTS ANALYSIS (HEAVILY MODIFIED)
# =============================================================================

def analyze_focused_results(results):
    """
    Analyze and display the best configurations.
    ## MODIFIED: This function now flattens the 'unseen_test_results'
    dictionary into separate columns for analysis.
    """
    if not results:
        print("❌ No results to analyze")
        return None
    
    print("\n📊 FOCUSED RESULTS ANALYSIS")
    print("=" * 60)
    
    results_list = []
    all_test_cipher_names = set()

    # First, flatten the results and find all unique test ciphers
    for config_id, result in results.items():
        row = result.copy()
        row['config_id'] = config_id
        
        # Pop the nested test results
        test_results = row.pop('unseen_test_results', {})
        
        if test_results:
            correct_count = 0
            for test_name, test_data in test_results.items():
                all_test_cipher_names.add(test_name)
                # Add flattened data to the row
                row[f"{test_name}_pred"] = test_data['prediction_label']
                row[f"{test_name}_correct"] = test_data['correct']
                row[f"{test_name}_confidence"] = test_data['confidence']
                if test_data['correct']:
                    correct_count += 1
            row['generalization_score'] = f"{correct_count}/{len(test_results)}"
            row['generalization_correct'] = correct_count
            row['generalization_total'] = len(test_results)
        
        results_list.append(row)
    
    df = pd.DataFrame(results_list)
    
    if df.empty:
        print("❌ Results DataFrame is empty. No configurations ran successfully.")
        return None
    
    # Define columns to display
    # 'dataset_size' is now included in base_cols
    base_cols = ['config_id', 'dataset_size', 'mean_f1', 'std_f1', 'mean_acc', 'std_acc', 'generalization_correct', 'generalization_total','model_type']
    
    # --- END OF FIX ---
    
    #base_cols = ['config_id', 'mean_f1', 'std_f1', 'mean_acc', 'std_acc']
    test_cols = []
    for name in sorted(list(all_test_cipher_names)):
        test_cols.extend([f"{name}_pred", f"{name}_correct", f"{name}_confidence"])

    # Ensure all columns exist, fill with NaN if they don't
    for col in base_cols + test_cols:
        if col not in df.columns:
            df[col] = np.nan
            
    # Reorder columns for clarity
    df = df[base_cols + ['generalization_score'] + test_cols + ['architecture']]

    print("\n🏆 BEST OVERALL CONFIGURATIONS:")
    
    # Best F1 score
    best_f1 = df.loc[df['mean_f1'].idxmax()]
    print(f"🎯 Best F1 Score: {best_f1['config_id']}")
    print(f"  F1: {best_f1['mean_f1']:.4f} ± {best_f1['std_f1']:.4f} (Acc: {best_f1['mean_acc']:.4f})")
    print(f"  Generalization: {best_f1['generalization_score']}")
    
    # Best Generalization
    if 'generalization_correct' in df.columns:
        best_gen_df = df[df['generalization_correct'] == df['generalization_correct'].max()]
        best_gen = best_gen_df.loc[best_gen_df['mean_f1'].idxmax()]
        print(f"🎯 Best Generalization Performance (with highest F1): {best_gen['config_id']}")
        print(f"  Generalization: {best_gen['generalization_score']}")
        print(f"  F1: {best_gen['mean_f1']:.4f} ± {best_gen['std_f1']:.4f} (Acc: {best_gen['mean_acc']:.4f})")
    else:
        print("🎯 No generalization results to report.")
    
    print(f"\n📈 PERFORMANCE BY DATASET SIZE:")
    for size in sorted(df['dataset_size'].unique()):
        size_results = df[df['dataset_size'] == size]
        avg_f1 = size_results['mean_f1'].mean()
        avg_gen_correct = size_results['generalization_correct'].mean()
        total_gen = size_results['generalization_total'].iloc[0] if not size_results.empty else 0
        print(f"  Size {size}: Avg F1={avg_f1:.4f}, Avg Generalization={avg_gen_correct:.2f}/{total_gen}")
    
    print(f"\n🤖 PERFORMANCE BY MODEL TYPE:")
    for model_type in df['model_type'].unique():
        model_results = df[df['model_type'] == model_type]
        avg_f1 = model_results['mean_f1'].mean()
        avg_gen_correct = model_results['generalization_correct'].mean()
        total_gen = model_results['generalization_total'].iloc[0] if not model_results.empty else 0
        best_config = model_results.loc[model_results['mean_f1'].idxmax()]['config_id']
        print(f"  {model_type:12}: Avg F1={avg_f1:.4f}, Avg Generalization={avg_gen_correct:.2f}/{total_gen}")
        print(f"     Best config: {best_config}")
    
    return df

# =============================================================================
# 7. MAIN EXECUTION PIPELINE (MODIFIED)
# =============================================================================

def _clean_results_for_json(data):
    """Recursively clean a dictionary of numpy types for JSON serialization."""
    if isinstance(data, dict):
        return {k: _clean_results_for_json(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_clean_results_for_json(v) for v in data]
    elif isinstance(data, np.floating):
        return float(data)
    elif isinstance(data, np.integer):
        return int(data)
    elif isinstance(data, np.bool_):
        return bool(data)
    else:
        return data

def run_focused_grid_pipeline():
    """Run the complete focused grid training pipeline"""
    print("🚀 FOCUSED GRID TRAINING PIPELINE (V3 - Multi-Test)")
    print("=" * 80)
    
    # ## MODIFIED: Pass the test directory name ##
    trainer = FocusedGridTrainingManager(
        base_data_dir="sampled_data_variant_based_balanced",
        test_ciphers_dir="test_only_ciphers"
    )
    
    results = trainer.run_focused_grid_training(
        dataset_sizes= [ 4, 5 ,6,7, 8, 9, 10, 11,1,2,3 ],
        
        model_types=['GCN', 'GAT', 'Transformer']
    )
    
    if results:
        df = analyze_focused_results(results)
        
        if df is not None:
            df.to_csv("focused_grid_results.csv", index=False)
            print(f"\n💾 Results saved to: focused_grid_results.csv")
            
            # ## MODIFIED: Use the recursive cleaning function for safe JSON dump ##
            with open("focused_grid_detailed_results.json", "w") as f:
                cleaned_results = _clean_results_for_json(results)
                json.dump(cleaned_results, f, indent=2)
            
            print(f"💾 Detailed results saved to: focused_grid_detailed_results.json")
            print(f"💾 Models saved to: best_models_focused/ directory")
            
            return df, results
        else:
            print("❌ Analysis failed, no CSV saved.")
            return None, None
    else:
        print("❌ Training failed - no results generated")
        return None, None


OUTPUT_MODELS_SAVED = 'best_models_focused'
FOCUSED_GRID_CONFIGS = {
    'GCN': [
        # Config 1: Robust Baseline (Norm + MaxPool handles scale)
        {'gcn_dims': [128, 128], 'pdv_dims': [64], 'classifier_dims': [128, 64],
         'lr': 0.001, 'dropout': 0.4, 'weight_decay': 1e-4, 'patience': 30, 'n_epochs': 300},
        
        # Config 2: Wider for sparse features
        {'gcn_dims': [160, 128], 'pdv_dims': [64], 'classifier_dims': [192, 64],
         'lr': 0.001, 'dropout': 0.5, 'weight_decay': 1e-4, 'patience': 30, 'n_epochs': 300},
    ],
    'GAT': [
        # Config 1: Attention Baseline (2 Heads)
        {'gat_dims': [64, 64], 'pdv_dims': [64], 'classifier_dims': [128, 64],
         'heads': 2, 'lr': 0.001, 'dropout': 0.4, 'weight_decay': 5e-4, 'patience': 30, 'n_epochs': 300},

        # Config 2: Multi-Head Focus (4 Heads)
        # 32 dim * 4 heads = 128 actual width
        {'gat_dims': [72, 64], 'pdv_dims': [64, 64], 'classifier_dims': [128, 80, 48],
         'heads': 2, 'lr': 0.001, 'dropout': 0.5, 'weight_decay': 3e-4, 'patience': 30, 'n_epochs': 300},

    ],
    
    'Transformer': [
        # Config 1: Transformer Baseline (2 Heads)
        {'transformer_dims': [64, 64], 'pdv_dims': [64], 'classifier_dims': [128, 64],
         'heads': 2, 'lr': 0.001, 'dropout': 0.4, 'weight_decay': 5e-4, 'patience': 30, 'n_epochs': 300},

        # Config 2: Deep Transformer (4 Heads, Wider Classifier)
        {'transformer_dims': [88, 64, 64], 'pdv_dims': [64,48], 'classifier_dims': [192, 64],
         'heads': 3, 'lr': 0.001, 'dropout': 0.5, 'weight_decay': 5e-4, 'patience': 30, 'n_epochs': 300},
    ]
}


if __name__ == "__main__":
    # Use the V3 (Data-Scarce) configs to avoid overfitting

    results_df, detailed_results = run_focused_grid_pipeline()