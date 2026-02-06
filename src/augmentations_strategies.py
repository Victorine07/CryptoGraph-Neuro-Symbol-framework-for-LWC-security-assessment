
import os
import json
import random
import copy
import re
from typing import Dict, Any, List, Set


# -----------------------
# IMPROVED CORE AUGMENTATIONS
# -----------------------


# Your existing utility functions are GOOD - keep them as-is
def load_json(file_path: str) -> Dict[str, Any]:
    """Load JSON file with error handling."""
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_json(data: Dict[str, Any], file_path: str):
    """Save JSON file with proper formatting."""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

def safe_truncate(text: str, max_length: int) -> str:
    """Safely truncate text to maximum length."""
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."

def recompute_op_counts_from_nodes_and_edges(ast: Dict[str, Any]):
    """Recompute operation counts from AST nodes after augmentation."""
    nodes = ast.get("nodes", [])
    
    # Count operations from nodes
    op_counts = {
        "xor_count": 0, "rotl_count": 0, "rotr_count": 0,
        "add_count": 0, "sub_count": 0, "and_count": 0,
        "sbox_count": 0, "perm_count": 0
    }
    
    for node in nodes:
        if node.get("type") == "op":
            label = node.get("label", "").upper()
            if label == "XOR":
                op_counts["xor_count"] += 1
            elif label == "ROTL":
                op_counts["rotl_count"] += 1
            elif label == "ROTR":
                op_counts["rotr_count"] += 1
            elif label == "ADD":
                op_counts["add_count"] += 1
            elif label == "SUB":
                op_counts["sub_count"] += 1
            elif label == "AND":
                op_counts["and_count"] += 1
            elif "SBOX" in label:
                op_counts["sbox_count"] += 1
            elif "PERM" in label:
                op_counts["perm_count"] += 1
    
    # Update the PDV
    if "pdv" in ast and "ops_summary" in ast["pdv"]:
        ast["pdv"]["ops_summary"].update(op_counts)

def recompute_graph_stats(ast: Dict[str, Any]):
    """Recompute graph statistics after augmentation."""
    nodes = ast.get("nodes", [])
    edges = ast.get("edges", [])
    functions = ast.get("functions", [])
    
    # Update unified PDV if it exists
    if "unified_pdv" in ast:
        ast["unified_pdv"]["ast_node_count"] = len(nodes)
        ast["unified_pdv"]["ast_edge_count"] = len(edges)
        ast["unified_pdv"]["function_count"] = len(functions)

# FIXED: Safer implementation that works with your actual AST structure
def safe_representation_variation(ast: Dict[str, Any]) -> Dict[str, Any]:
    """
    Change representation without changing semantics - SAFE VERSION
    Only modifies metadata, not actual operations
    """
    new_ast = copy.deepcopy(ast)
    
    # Add representation metadata to nodes without changing operations
    for node in new_ast.get("nodes", []):
        if node.get("type") in ["op", "function"]:
            # Initialize features if not present
            if "features" not in node:
                node["features"] = {}
            
            # Add representation variant as metadata only
            variants = ["direct", "decomposed", "optimized", "canonical"]
            node["features"]["representation_variant"] = random.choice(variants)
    
    return new_ast

# FIXED: Metadata-only versions for cipher-specific strategies
def safe_present_sbox_representation(ast: Dict[str, Any]) -> Dict[str, Any]:
    """
    Vary S-box representation in PRESENT - METADATA ONLY
    """
    if ast.get("pdv", {}).get("cipher_family") != "PRESENT":
        return ast
    
    new_ast = copy.deepcopy(ast)
    
    sbox_representations = ["lookup_table", "computed_form", "bit_sliced", "algebraic_form"]
    
    for node in new_ast.get("nodes", []):
        if (node.get("type") == "function" and 
            any(sbox_keyword in node.get("label", "").lower() 
                for sbox_keyword in ["sbox", "present_sbox"])):
            
            if "features" not in node:
                node["features"] = {}
            node["features"]["sbox_representation"] = random.choice(sbox_representations)
    
    return new_ast

def safe_present_permutation_variation(ast: Dict[str, Any]) -> Dict[str, Any]:
    """
    Vary permutation layer implementation - METADATA ONLY
    """
    if ast.get("pdv", {}).get("cipher_family") != "PRESENT":
        return ast
    
    new_ast = copy.deepcopy(ast)
    
    permutation_variants = ["bitwise_mapping", "matrix_rotation", "word_operations", "parallel_blocks"]
    
    for node in new_ast.get("nodes", []):
        if (node.get("type") == "function" and 
            any(perm_keyword in node.get("label", "").lower() 
                for perm_keyword in ["p_layer", "permutation"])):
            
            if "features" not in node:
                node["features"] = {}
            node["features"]["permutation_implementation"] = random.choice(permutation_variants)
    
    return new_ast

def safe_present_round_structure_variation(ast: Dict[str, Any]) -> Dict[str, Any]:
    """
    Vary PRESENT round function implementation - METADATA ONLY
    """
    if ast.get("pdv", {}).get("cipher_family") != "PRESENT":
        return ast
    
    new_ast = copy.deepcopy(ast)
    
    round_variants = ["sequential", "integrated", "parallel", "pipelined"]
    
    for node in new_ast.get("nodes", []):
        if (node.get("type") == "function" and 
            "present_round" in node.get("label", "").lower()):
            
            if "features" not in node:
                node["features"] = {}
            node["features"]["round_implementation"] = random.choice(round_variants)
    
    return new_ast

def safe_key_schedule_representation(ast: Dict[str, Any]) -> Dict[str, Any]:
    """
    Vary key schedule implementation - METADATA ONLY
    """
    new_ast = copy.deepcopy(ast)
    
    variants = ["recursive", "iterative", "unrolled", "table_based"]
    
    for node in new_ast.get("nodes", []):
        if (node.get("type") == "function" and 
            "key" in node.get("label", "").lower() and 
            "schedule" in node.get("label", "").lower()):
            
            if "features" not in node:
                node["features"] = {}
            node["features"]["implementation_variant"] = random.choice(variants)
    
    return new_ast


def safe_commutative_operation_reordering(ast: Dict[str, Any]) -> Dict[str, Any]:
    """
     Reorder commutative operations with dependency checking
    """
    new_ast = copy.deepcopy(ast)
    
    for func_name, op_sequence in new_ast.get("op_sequences", {}).items():
        if len(op_sequence) < 2:
            continue
            
        new_sequence = []
        i = 0
        
        while i < len(op_sequence):
            if op_sequence[i] in {"XOR", "ADD"}:
                # Find consecutive commutative operations
                j = i
                while j < len(op_sequence) and op_sequence[j] in {"XOR", "ADD"}:
                    j += 1
                
                # Only shuffle if no obvious dependencies in sequence
                block = op_sequence[i:j]
                if len(block) > 1 and _is_independent_block(block, func_name, new_ast):
                    random.shuffle(block)
                new_sequence.extend(block)
                i = j
            else:
                new_sequence.append(op_sequence[i])
                i += 1
        
        new_ast["op_sequences"][func_name] = new_sequence
    
    return new_ast

def _is_independent_block(block: List[str], func_name: str, ast: Dict[str, Any]) -> bool:
    """
    Check if operations in block are likely independent
    Conservative approach: assume dependent if complex structure
    """
    # For now, use simple heuristic - allow shuffling for short blocks
    return len(block) <= 4

def safe_function_renaming(ast: Dict[str, Any]) -> Dict[str, Any]:
    """
     Rename helper functions with crypto-core protection
    """
    new_ast = copy.deepcopy(ast)
    
    # Core cryptographic functions to NEVER rename
    CRYPTO_CORE_FUNCTIONS = {
        "encrypt", "decrypt", "round", "key", "schedule", "sbox", "p_layer",
        "F_function", "simon_round", "speck_enc_round", "speck_dec_round",
        "present_round", "present_sbox", "generate_key_schedule"
    }
    
    # Safe helper prefixes/suffixes
    SAFE_HELPERS = {"helper", "aux", "temp", "compute", "calculate", "process"}
    
    rename_map = {}
    nodes = new_ast.get("nodes", [])
    
    # Identify safe functions to rename
    for node in nodes:
        if node.get("type") == "function":
            label = node.get("label", "").lower()
            
            # Check if this is a crypto core function
            is_core_function = any(core in label for core in CRYPTO_CORE_FUNCTIONS)
            is_safe_helper = any(helper in label for helper in SAFE_HELPERS)
            
            if is_safe_helper and not is_core_function:
                old_name = node["label"]
                new_name = f"{old_name}_v{random.randint(1, 3)}"
                rename_map[old_name] = new_name
                node["label"] = new_name
    
    # Update references
    if rename_map:
        for node in nodes:
            if node.get("type") == "function_call" and node["label"] in rename_map:
                node["label"] = rename_map[node["label"]]
        
        # Update functions list
        for func in new_ast.get("functions", []):
            if func["name"] in rename_map:
                func["name"] = rename_map[func["name"]]
        
        # Update op_sequences keys
        if "op_sequences" in new_ast:
            new_ops = {}
            for k, v in new_ast["op_sequences"].items():
                new_ops[rename_map.get(k, k)] = v
            new_ast["op_sequences"] = new_ops
    
    return new_ast

def safe_bit_operation_commutativity(ast: Dict[str, Any]) -> Dict[str, Any]:
    """
     Safe bit operation reordering (removed directional shifts)
    """
    new_ast = copy.deepcopy(ast)
    
    # ONLY truly commutative bit operations
    commutative_bit_ops = {
        "bitwise_and", "bitwise_or", "bitwise_xor"
    }
    
    for func_name, op_sequence in new_ast.get("op_sequences", {}).items():
        if len(op_sequence) < 2:
            continue
            
        new_sequence = []
        i = 0
        
        while i < len(op_sequence):
            if op_sequence[i] in commutative_bit_ops:
                # Find consecutive commutative operations
                j = i
                while j < len(op_sequence) and op_sequence[j] in commutative_bit_ops:
                    j += 1
                
                # Shuffle this commutative block
                block = op_sequence[i:j]
                if len(block) > 1:
                    random.shuffle(block)
                new_sequence.extend(block)
                i = j
            else:
                new_sequence.append(op_sequence[i])
                i += 1
        
        new_ast["op_sequences"][func_name] = new_sequence
    
    return new_ast

# -----------------------
# NEW AUGMENTATION STRATEGIES
# -----------------------

def safe_temporary_variable_renaming(ast: Dict[str, Any]) -> Dict[str, Any]:
    """
     Rename temporary/local variables without changing logic
    """
    new_ast = copy.deepcopy(ast)
    
    # Common temporary variable patterns
    temp_patterns = {"tmp", "temp", "x", "y", "z", "a", "b", "c", "var", "val"}
    
    rename_map = {}
    nodes = new_ast.get("nodes", [])
    
    # Identify temporary variables to rename
    for node in nodes:
        if node.get("type") == "var":
            var_name = node.get("label", "")
            
            # Only rename if it looks like a temporary
            if (var_name.lower() in temp_patterns or 
                re.match(r'^[a-z]$', var_name) or  # Single letter
                re.match(r'^tmp\d*$', var_name.lower())):  # tmp123
                
                new_name = f"{var_name}_{random.randint(1, 9)}"
                rename_map[var_name] = new_name
                node["label"] = new_name
    
    # Update variable references in function bodies
    if rename_map:
        for node in nodes:
            if node.get("type") == "function" and "body_text" in node.get("features", {}):
                body = node["features"]["body_text"]
                for old_name, new_name in rename_map.items():
                    # Use word boundaries to avoid partial replacements
                    body = re.sub(r'\b' + re.escape(old_name) + r'\b', new_name, body)
                node["features"]["body_text"] = safe_truncate(body, 300)
    
    return new_ast

def safe_comment_whitespace_injection(ast: Dict[str, Any]) -> Dict[str, Any]:
    """
     Add synthetic comments and whitespace variations
    """
    new_ast = copy.deepcopy(ast)
    
    comment_templates = [
        "(* Helper computation *)",
        "(* Temporary variable *)", 
        "(* Cryptographic operation *)",
        "(* Bit manipulation *)",
        "(* Round function component *)"
    ]
    
    for node in new_ast.get("nodes", []):
        if node.get("type") == "function" and "body_text" in node.get("features", {}):
            body = node["features"]["body_text"]
            
            # Occasionally add a comment at the beginning
            if random.random() < 0.3:
                comment = random.choice(comment_templates)
                body = f"{comment}\n{body}"
            
            # Add some whitespace variations
            if random.random() < 0.4:
                # Randomly add/remove some newlines
                lines = body.split('\n')
                if len(lines) > 2:
                    # Occasionally add an extra newline
                    if random.random() < 0.3:
                        insert_pos = random.randint(1, len(lines)-1)
                        lines.insert(insert_pos, "")
                    body = '\n'.join(lines)
            
            node["features"]["body_text"] = safe_truncate(body, 300)
    
    return new_ast

def safe_annotation_augmentation(ast: Dict[str, Any]) -> Dict[str, Any]:
    """
     Add synthetic Isabelle annotations
    """
    new_ast = copy.deepcopy(ast)
    
    annotations = [
        "(*@ verified *)",
        "(*@ inline *)", 
        "(*@ pure *)",
        "(*@ preserves_crypto *)",
        "(*@ preserves_semantics *)"
    ]
    
    for node in new_ast.get("nodes", []):
        if node.get("type") == "function" and "body_text" in node.get("features", {}):
            body = node["features"]["body_text"]
            
            # Add annotation with some probability
            if random.random() < 0.25:
                annotation = random.choice(annotations)
                body = f"{annotation}\n{body}"
                node["features"]["body_text"] = safe_truncate(body, 300)
            
            # Add annotation metadata to features
            features = node.get("features", {})
            if "annotations" not in features:
                features["annotations"] = []
            if random.random() < 0.2:
                features["annotations"].append(random.choice(["verified", "pure", "inline"]))
            node["features"] = features
    
    return new_ast

def safe_function_inlining(ast: Dict[str, Any]) -> Dict[str, Any]:
    """
     Replace simple helper function calls with metadata
    (Doesn't actually inline, just marks for representation)
    """
    new_ast = copy.deepcopy(ast)
    
    for node in new_ast.get("nodes", []):
        if node.get("type") == "function_call":
            # Mark some calls as "inlinable" in metadata
            func_name = node.get("label", "")
            
            # Simple heuristics for inlinable functions
            is_simple_helper = any(pattern in func_name.lower() 
                                 for pattern in ["helper", "compute", "calculate", "get"])
            
            if is_simple_helper and random.random() < 0.3:
                features = node.get("features", {})
                features["inlinable"] = True
                features["inline_variant"] = random.choice(["direct", "expanded", "optimized"])
                node["features"] = features
    
    return new_ast

# -----------------------
# ENHANCED STRATEGY LISTS
# -----------------------

# Core strategies (high impact, very safe)
CORE_AUG_STRATEGIES = [
    safe_commutative_operation_reordering,
    safe_function_renaming,
    safe_temporary_variable_renaming,
    safe_representation_variation,
]

# Textual variation strategies (safe, adds diversity)
TEXTUAL_AUG_STRATEGIES = [
    safe_comment_whitespace_injection,
    safe_annotation_augmentation,
]

# Cipher-specific strategies
PRESENT_SPECIFIC_STRATEGIES = CORE_AUG_STRATEGIES + [
    safe_bit_operation_commutativity,
    safe_present_sbox_representation,
    safe_present_permutation_variation,
    safe_present_round_structure_variation,
] + TEXTUAL_AUG_STRATEGIES

SPECK_SPECIFIC_STRATEGIES = CORE_AUG_STRATEGIES + [
    safe_key_schedule_representation,
] + TEXTUAL_AUG_STRATEGIES

SIMON_SPECIFIC_STRATEGIES = CORE_AUG_STRATEGIES + [
    safe_key_schedule_representation, 
] + TEXTUAL_AUG_STRATEGIES

AUGMENTATION_STRATEGIES = {
    "Simon": SIMON_SPECIFIC_STRATEGIES,
    "Speck": SPECK_SPECIFIC_STRATEGIES,
    "PRESENT": PRESENT_SPECIFIC_STRATEGIES
}

# Strategy weights for sampling (higher = more frequent)
STRATEGY_WEIGHTS = {
    safe_commutative_operation_reordering: 2.0,  # High impact
    safe_function_renaming: 1.5,                 # Medium impact  
    safe_temporary_variable_renaming: 1.2,       # Medium impact
    safe_representation_variation: 1.0,          # Medium impact
    safe_comment_whitespace_injection: 0.8,      # Lower impact
    safe_annotation_augmentation: 0.7,           # Lower impact
    safe_function_inlining: 0.6,                 # Lower impact
}



def weighted_strategy_sampling(strategies: List, num_strategies: int) -> List:
    """
    Sample strategies based on weights for more intelligent augmentation
    """
    if not strategies:
        return []
    
    # Get weights for available strategies
    available_weights = [STRATEGY_WEIGHTS.get(s, 1.0) for s in strategies]
    
    # Normalize weights
    total_weight = sum(available_weights)
    if total_weight == 0:
        return random.sample(strategies, min(num_strategies, len(strategies)))
    
    normalized_weights = [w / total_weight for w in available_weights]
    
    # Sample without replacement using weights
    selected = []
    remaining_strategies = strategies.copy()
    remaining_weights = normalized_weights.copy()
    
    for _ in range(min(num_strategies, len(strategies))):
        if not remaining_strategies:
            break
            
        # Weighted random choice
        chosen_idx = random.choices(
            range(len(remaining_strategies)), 
            weights=remaining_weights
        )[0]
        
        selected.append(remaining_strategies[chosen_idx])
        
        # Remove selected strategy
        remaining_strategies.pop(chosen_idx)
        remaining_weights.pop(chosen_idx)
        
        # Re-normalize weights
        total_remaining = sum(remaining_weights)
        if total_remaining > 0:
            remaining_weights = [w / total_remaining for w in remaining_weights]
    
    return selected


def safe_feature_noise_injection(ast: Dict[str, Any], noise_level: float = 0.05) -> Dict[str, Any]:
    """
    Add small Gaussian noise to continuous numerical features.
    """
    new_ast = copy.deepcopy(ast)
    
    for node in new_ast.get("nodes", []):
        # Add noise to the root numerical features
        for key in ["crypto_strength", "diffusion_power", "nonlinearity"]:
            if key in node and isinstance(node[key], (int, float)):
                if node[key] > 0: # Only add noise to non-zero features
                    noise = random.gauss(0, noise_level)
                    node[key] = max(0, node[key] * (1 + noise)) # Ensure non-negative

        # Add noise to features in the 'features' sub-dict (if you use it)
        if "features" in node and isinstance(node["features"], dict):
            for key, value in node["features"].items():
                if isinstance(value, (int, float)) and value > 0 and random.random() < 0.2:
                    noise = random.gauss(0, noise_level)
                    node["features"][key] = max(0, value * (1 + noise))
    
    return new_ast

def safe_node_dropout_cryptographic(ast: Dict[str, Any], p: float = 0.15) -> Dict[str, Any]:
    """
    Enhanced node dropout that understands cryptographic semantics
    (Deepseek's excellent version)
    """
    new_ast = copy.deepcopy(ast)
    nodes = new_ast.get("nodes", [])
    
    if len(nodes) < 15:  # Don't augment very small graphs
        return new_ast

    # CRYPTOGRAPHIC SEMANTICS: Define what can NEVER be dropped
    NEVER_DROP_ROLES = {
        "feistel_f_function", "sbox_substitution", "permutation_layer",
        "modular_addition", "nonlinear_mixing"
    }
    
    NEVER_DROP_LABELS = {
        "round", "encrypt", "decrypt", "key_schedule", "F_function",
        "sbox", "p_layer", "present_round", "simon_round", "speck_enc_round"
    }

    # Classify nodes by cryptographic importance
    critical_node_ids = set()
    droppable_nodes = []

    for node in nodes:
        is_critical = False
        if node.get("crypto_role") in NEVER_DROP_ROLES:
            is_critical = True
        for label in NEVER_DROP_LABELS:
            if label in node.get("label", "").lower():
                is_critical = True
        
        if is_critical:
            critical_node_ids.add(node["id"])
        else:
            droppable_nodes.append(node)

    # Apply dropout with cryptographic awareness
    if droppable_nodes:
        num_to_drop = max(1, int(len(droppable_nodes) * p))
        nodes_to_drop = random.sample(droppable_nodes, num_to_drop)
        ids_to_drop = {node["id"] for node in nodes_to_drop}
        
        new_ast["nodes"] = [n for n in nodes if n["id"] not in ids_to_drop]
        new_ast["edges"] = [
            e for e in new_ast.get("edges", [])
            if e["source"] not in ids_to_drop and e["target"] not in ids_to_drop
        ]
        
        # Track what was dropped for analysis
        if "pdv" not in new_ast: new_ast["pdv"] = {}
        if "augmentation_metadata" not in new_ast["pdv"]: new_ast["pdv"]["augmentation_metadata"] = {}
        
        aug_meta = new_ast["pdv"]["augmentation_metadata"]
        aug_meta["node_dropout_count"] = num_to_drop
        aug_meta["dropped_node_types"] = list(set(n.get("type") for n in nodes_to_drop))

    return new_ast

def safe_edge_perturbation_cryptographic(ast: Dict[str, Any], p_drop: float = 0.08, p_add: float = 0.05) -> Dict[str, Any]:
    """
    Edge perturbation that respects cryptographic data flow
    (Deepseek's excellent version)
    """
    new_ast = copy.deepcopy(ast)
    nodes = new_ast.get("nodes", [])
    edges = new_ast.get("edges", [])
    
    if not edges:
        return new_ast

    # NEVER drop these critical edge types
    CRITICAL_EDGE_TYPES = {"contains", "func", "amount"}  # Structural edges
    
    # Safe to drop these edge types
    DROPPABLE_EDGE_TYPES = {"arg", "child", "left", "right", "binding", "body"}
    
    # Separate edges by importance
    critical_edges = [e for e in edges if e.get("type") in CRITICAL_EDGE_TYPES]
    droppable_edges = [e for e in edges if e.get("type") in DROPPABLE_EDGE_TYPES]
    
    # Edge dropping (only from droppable set)
    num_edges_to_drop = max(1, int(len(droppable_edges) * p_drop))
    remaining_edges = critical_edges
    if droppable_edges and num_edges_to_drop > 0:
        edges_to_keep = random.sample(droppable_edges, len(droppable_edges) - num_edges_to_drop)
        remaining_edges.extend(edges_to_keep)
    else:
        remaining_edges.extend(droppable_edges)
    
    # Edge addition (create semantically plausible new connections)
    new_edges = []
    num_edges_to_add = max(1, int(len(edges) * p_add))
    
    source_candidates = [n["id"] for n in nodes if n.get("type") in ["op", "function", "var", "literal"]]
    target_candidates = [n["id"] for n in nodes if n.get("type") in ["op", "function"]]
    
    for _ in range(num_edges_to_add):
        if source_candidates and target_candidates:
            source_id = random.choice(source_candidates)
            target_id = random.choice(target_candidates)
            
            if (source_id != target_id and
                not any(e["source"] == source_id and e["target"] == target_id 
                        for e in remaining_edges + new_edges)):
                
                new_edge = {
                    "source": source_id,
                    "target": target_id,
                    "type": "arg",  # A plausible, droppable type
                    "features": {"synthetic": True, "augmentation": "edge_add"}
                }
                new_edges.append(new_edge)
    
    new_ast["edges"] = remaining_edges + new_edges
    
    # Update metadata
    if "pdv" not in new_ast: new_ast["pdv"] = {}
    if "augmentation_metadata" not in new_ast["pdv"]: new_ast["pdv"]["augmentation_metadata"] = {}
    
    aug_meta = new_ast["pdv"]["augmentation_metadata"]
    aug_meta["edge_perturb_drop"] = num_edges_to_drop
    aug_meta["edge_perturb_add"] = len(new_edges)

    return new_ast
    

# Core strategies (high impact, very safe)
CORE_AUG_STRATEGIES = [
    safe_node_dropout_cryptographic,          #
    safe_edge_perturbation_cryptographic,     # 
    safe_commutative_operation_reordering,
    safe_function_renaming,
    safe_temporary_variable_renaming,
    safe_representation_variation,
]

# Textual/Noise variation strategies (safe, adds diversity)
TEXTUAL_AUG_STRATEGIES = [
    safe_feature_noise_injection,             # 
    safe_comment_whitespace_injection,
    safe_annotation_augmentation,
]

# Cipher-specific strategies
PRESENT_SPECIFIC_STRATEGIES = CORE_AUG_STRATEGIES + [
    safe_bit_operation_commutativity,
    safe_present_sbox_representation,
    safe_present_permutation_variation,
    safe_present_round_structure_variation,
] + TEXTUAL_AUG_STRATEGIES

SPECK_SPECIFIC_STRATEGIES = CORE_AUG_STRATEGIES + [
    safe_key_schedule_representation,
] + TEXTUAL_AUG_STRATEGIES

SIMON_SPECIFIC_STRATEGIES = CORE_AUG_STRATEGIES + [
    safe_key_schedule_representation,  
] + TEXTUAL_AUG_STRATEGIES

AUGMENTATION_STRATEGIES = {
    "Simon": SIMON_SPECIFIC_STRATEGIES,
    "Speck": SPECK_SPECIFIC_STRATEGIES,
    "PRESENT": PRESENT_SPECIFIC_STRATEGIES
}

# --- NEW WEIGHTS ---
STRATEGY_WEIGHTS = {
    # Structural (Highest Impact)
    safe_node_dropout_cryptographic: 3.0,
    safe_edge_perturbation_cryptographic: 2.5,
    safe_commutative_operation_reordering: 2.0,
    
    # Metadata (Medium Impact)
    safe_function_renaming: 1.5,
    safe_temporary_variable_renaming: 1.2,
    safe_representation_variation: 1.0,

    # Noise/Textual (Regularization)
    safe_feature_noise_injection: 1.0,
    safe_comment_whitespace_injection: 0.5,
    safe_annotation_augmentation: 0.5,
}

### AUGMENTATIONS


# Configuration
AUGMENTED_DIR = "augmented_data"
AUG_PER_FILE = 10 # Number of augmented variants per original file

#SOURCE_DIR_ = 'output_ast'
SOURCE_DIR_ = 'augmented_data_0'


def mandatory_strict_anonymization(ast: Dict[str, Any]) -> Dict[str, Any]:
    """
    MANDATORY: Replaces ALL function names, references, contexts, and string literals
    with generic tokens (FUNC_0, FUNC_1...) to prevent leakage.
    """
    new_ast = copy.deepcopy(ast)
    nodes = new_ast.get("nodes", [])
    
    # 1. Identify and Map Function Definitions
    func_nodes = [n for n in nodes if n.get("type") in ["function", "func_name"]]
    func_nodes.sort(key=lambda x: x["id"])
    
    anonymization_map = {}
    for idx, node in enumerate(func_nodes):
        old_label = node.get("label", "")
        # Remove quotes if present for the mapping key
        clean_old_label = old_label.strip('"')
        
        new_label = f"FUNC_{idx}"
        
        # Map both raw and quoted versions
        anonymization_map[clean_old_label] = new_label
        anonymization_map[f'"{clean_old_label}"'] = new_label
        anonymization_map[f'"{clean_old_label}'] = new_label # Catch leading quote only
        
        # Update definition
        node["label"] = new_label
        if "context" in node:
            node["context"] = "anonymized_func"

    # 2. Aggressive Global Scrubbing
    forbidden_terms = ["simon", "speck", "present", "simeck", "lea", "hight", "gift", "rectangle", "sparx", "xtea", "hight","skinny"]
    
    for node in nodes:
        # A. SCRUB LABELS (Function calls, Variables, Strings)
        label = str(node.get("label", ""))
        
        # Check against map
        if label in anonymization_map:
            node["label"] = anonymization_map[label]
        # Check for substrings (e.g., "simon_round" inside a longer string)
        else:
            for old, new in anonymization_map.items():
                if old in label and len(old) > 2: # Avoid replacing short common strings
                    label = label.replace(old, new)
                    node["label"] = label
        
        # Final Safety Net: If a forbidden term persists, nuke it
        if any(term in label.lower() for term in forbidden_terms):
            # Try to save it if it's a known function
            found = False
            for old, new in anonymization_map.items():
                if old in label:
                    node["label"] = label.replace(old, new)
                    found = True
                    break
            if not found:
                # Last resort: Generic masking
                node["label"] = "ANONYMIZED_TERM"

        # B. SCRUB CONTEXT (The main leak you found)
        context = str(node.get("context", ""))
        
        # If context matches a known function name
        if context in anonymization_map:
             node["context"] = anonymization_map[context]
        # Or if it contains a forbidden term
        elif any(term in context.lower() for term in forbidden_terms):
             node["context"] = "anonymized_context"

    # 3. Update top-level lists
    new_funcs = []
    for f in new_ast.get("functions", []):
        clean_f = f.strip('"')
        if clean_f in anonymization_map:
            new_funcs.append(anonymization_map[clean_f])
        else:
            # Fallback for unmapped functions
            sanitized = f
            for term in forbidden_terms:
                if term in sanitized.lower():
                    sanitized = "ANONYMIZED_FUNC"
            new_funcs.append(sanitized)
    new_ast["functions"] = new_funcs

    # 4. Update op_sequences
    if "op_sequences" in new_ast:
        new_ops = {}
        for k, v in new_ast["op_sequences"].items():
            clean_k = k.strip('"')
            new_key = anonymization_map.get(clean_k, k)
            if any(term in new_key.lower() for term in forbidden_terms):
                 new_key = "ANONYMIZED_SEQ"
            new_ops[new_key] = v
        new_ast["op_sequences"] = new_ops

    if "pdv" not in new_ast: new_ast["pdv"] = {}
    new_ast["pdv"]["anonymized"] = True
    
    return new_ast
    
    
def run_progressive_augmentation():
    """
    Creates multiple augmented datasets with increasing size
    based on the 23 original files.
    """
    
    # Your 23 original files are in "dataset-1"
    SOURCE_DIR = SOURCE_DIR_ 
    
    # We will create 3 new output directories
    OUTPUT_BASE_DIR = AUGMENTED_DIR

    CIPHERS = ["Simon", "Speck", "PRESENT", "gift", "lea", "rectangle", "simeck", "sparx", "xtea" , "HIGHT", "SKINNY"]
    
    
    PROGRESSIVE_AUGMENTATION_PLANS = {
        'dataset-12x': {
            'augmentations_per_file': 10,  # 7 augs + 1 original = 8x
            'node_dropout_p': 0.1,
            'edge_perturb_p': 0.05,
            'noise_level': 0.02
        },

    }

    for plan_name, plan_config in PROGRESSIVE_AUGMENTATION_PLANS.items():
        print(f"\n--- Generating {plan_name} ---")
        num_augs = plan_config['augmentations_per_file']
        #output_dir_plan = os.path.join(OUTPUT_BASE_DIR, plan_name)
        output_dir_plan = os.path.join(OUTPUT_BASE_DIR, '')
        
        total_graphs = 0
        
        for cipher_name in CIPHERS:
            source_cipher_dir = os.path.join(SOURCE_DIR, cipher_name)
            output_cipher_dir = os.path.join(output_dir_plan, cipher_name)
            
            if not os.path.exists(source_cipher_dir):
                print(f"Warning: Source dir not found: {source_cipher_dir}")
                continue

            strategies = AUGMENTATION_STRATEGIES.get(cipher_name, CORE_AUG_STRATEGIES)
            json_files = [f for f in os.listdir(source_cipher_dir) 
                          if f.endswith(".json") and not f.startswith("_")]
            
            print(f"Processing {cipher_name}: {len(json_files)} original files...")

            for json_file in json_files:
                input_path = os.path.join(source_cipher_dir, json_file)
                try:
                    original_ast = load_json(input_path)
                    
                    # Create N augmented variants
                    # We pass the p_... values to the augmentation function
                    variants = create_enhanced_augmented_variants_progressive(
                        original_ast, 
                        num_augs, 
                        strategies,
                        plan_config
                    )
                    
                    base_name = json_file.replace(".json", "")
                    for i, variant in enumerate(variants):
                        if i == 0:
                            output_name = f"{base_name}_original.json"
                        else:
                            output_name = f"{base_name}_aug{i}.json"
                        
                        output_path = os.path.join(output_cipher_dir, output_name)
                        save_json(variant, output_path)
                        total_graphs += 1

                except Exception as e:
                    print(f"  Error processing {json_file}: {e}")
                    
        print(f" Finished {plan_name}. Total graphs: {total_graphs}")


def create_enhanced_augmented_variants_progressive(original_ast: Dict[str, Any], 
                                                   num_variants: int, 
                                                   strategies: List,
                                                   plan_config: Dict) -> List[Dict[str, Any]]:
    """
    Modified creation function that accepts progressive scaling parameters.
    """
    
    # We anonymize the input AST first. This `secure_ast` has NO "Simon" or "Speck" names.
    secure_ast = mandatory_strict_anonymization(original_ast)
    
    
    variants = [copy.deepcopy(secure_ast)] # Include original
    
    # Get parameters from the plan
    p_node_drop = plan_config['node_dropout_p']
    p_edge_drop = plan_config['edge_perturb_p']
    p_edge_add = plan_config['edge_perturb_p'] / 2 # Add fewer than we drop
    noise_lvl = plan_config['noise_level']

    for i in range(num_variants):
        augmented_ast = copy.deepcopy(secure_ast)
        
        num_augmentations = random.randint(2, 4) # Apply 2-4 strategies per variant
        applied_strategies_fns = weighted_strategy_sampling(strategies, num_augmentations)
        
        applied_strategies_names = []

        for strategy_fn in applied_strategies_fns:
            try:
                # This is how you pass parameters to specific functions
                if strategy_fn == safe_node_dropout_cryptographic:
                    augmented_ast = strategy_fn(augmented_ast, p=p_node_drop)
                elif strategy_fn == safe_edge_perturbation_cryptographic:
                    augmented_ast = strategy_fn(augmented_ast, p_drop=p_edge_drop, p_add=p_edge_add)
                elif strategy_fn == safe_feature_noise_injection:
                    augmented_ast = strategy_fn(augmented_ast, noise_level=noise_lvl)
                else:
                    augmented_ast = strategy_fn(augmented_ast)
                
                applied_strategies_names.append(strategy_fn.__name__)
            except Exception as e:
                print(f"Warning: Strategy {strategy_fn.__name__} failed: {e}")
        
        # Recompute stats AFTER all augmentations
        recompute_op_counts_from_nodes_and_edges(augmented_ast)
        recompute_graph_stats(augmented_ast)
        
        # Update metadata
        if "pdv" not in augmented_ast: augmented_ast["pdv"] = {}
        augmented_ast["pdv"]["augmented"] = True
        augmented_ast["pdv"]["augmentation_metadata"] = {
            "strategies": applied_strategies_names,
            "variant_id": i + 1
        }
        
        # Preserve labels
        if "security_score" in original_ast:
            augmented_ast["security_score"] = original_ast["security_score"]
        if "security_label" in original_ast:
            augmented_ast["security_label"] = original_ast["security_label"]
        
        variants.append(augmented_ast)
    
    return variants


if __name__ == "__main__":
    # 1. Run the progressive augmentation to create your new datasets
    run_progressive_augmentation()
    
    pass













