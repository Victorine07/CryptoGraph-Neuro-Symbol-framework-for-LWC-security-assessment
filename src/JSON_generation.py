# MORE IN DEPTH EXTRACTION
import os
import re
import json
import math
import traceback
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Tuple, Optional

from cipher_profiles import SecurityParams, ATTACK_DB, compute_security_score, security_label_from_score, DEFAULT_PARAMS, CIPHER_PROFILES


all_label_computations = {}

def inline_constants(content: str) -> str:
    """
    Finds simple definitions (constants) and replaces their usage 
    in the text with the actual value.
    """
    const_pattern = r'definition\s+(\w+)\s*::.*?\s*where\s*"\1\s*=\s*([^"]+)"'
    
    definitions = re.findall(const_pattern, content)
    
    # Sort by length (descending) to prevent substring replacement issues
    # e.g., replace "CONST_12" before "CONST_1"
    definitions.sort(key=lambda x: len(x[0]), reverse=True)
    
    modified_content = content
    
    for name, value in definitions:
        # cleanup value (remove extra spaces)
        clean_value = value.strip()
        
        replacement = f"({clean_value})"
        
        # Regex: \bNAME\b ensures we don't match NAME_2
        modified_content = re.sub(rf'\b{name}\b', replacement, modified_content)
        
    return modified_content

# =============================================================================
# ENHANCED UNIFIED PDV PROCESSOR WITH CRYPTOGRAPHIC DEPTH
# =============================================================================

class LineByLineFunctionExtractor:
    """Extract functions line by line to properly stop at next keywords"""
    @staticmethod 
    def extract_core_functions(content: str, cipher_family: str, debug: bool = False) -> Tuple[Dict[str, str], List[str]]:
        """Extract core functions using line-by-line parsing"""
        
        clean_content = LineByLineFunctionExtractor._remove_comments(content)
        lines = clean_content.split('\n')
        
        core_functions = {}  # function_name -> function_body
        found_functions = []  # list of function names found
        
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            
            # Check if this line starts a function definition
            if LineByLineFunctionExtractor._is_function_start(line):
                func_name = LineByLineFunctionExtractor._extract_function_name(line)
                
                # Check if this function matches our core patterns
                if func_name and LineByLineFunctionExtractor._is_core_function(func_name, cipher_family):
                    # Extract the entire function body
                    func_body, new_index = LineByLineFunctionExtractor._extract_function_body(lines, i)
                    
                    if func_body:
                        core_functions[func_name] = func_body
                        found_functions.append(func_name)
                    
                    i = new_index  # Skip to after the function
                    continue
            
            i += 1
        
        if debug:
            print(f"\n=== EXTRACTED CORE FUNCTIONS for {cipher_family} ===")
            for func_name in found_functions:
                print(f"- {func_name}")
                # Print first few lines of the body for verification
                body_lines = core_functions[func_name].split('\n')
                preview = '\n'.join(body_lines[:3]) + "..." if len(body_lines) > 3 else core_functions[func_name]
                print(f"  Body preview: {preview[:100]}...")
        
        return core_functions, found_functions
    
    @staticmethod
    def _is_function_start(line: str) -> bool:
        """Check if line starts a function definition"""
        return any(line.startswith(keyword) for keyword in 
                  ['definition', 'fun', 'function', 'primrec'])
    
    @staticmethod
    def _extract_function_name(line: str) -> Optional[str]:
        """Extract function name from definition line"""
        patterns = [
            r'^(definition|fun|function|primrec)\s+(\w+)\s*::',
            r'^(definition|fun|function|primrec)\s+(\w+)\s*where',
        ]
        
        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                return match.group(2)
        return None
    
    @staticmethod
    def _is_core_function(func_name: str, cipher_family: str) -> bool:
        """FIXED: More accurate core function detection based on actual theory files"""
        
        # EXCLUDE configuration and helper functions
        excluded_functions = {
            'get_num_rounds', 'get_z_array_index', 'get_z_bit_val',
            'z0', 'z1', 'z2', 'z3', 'z4', 'rho_const', 'block_size',
            'key_size', 'word_size', 'num_rounds', 'get_shift_params',
            'alpha', 'beta', 'sbox_table', 'sbox_inv_table', 'p_layer_map',
            'p_layer_inv_map', 'extract_round_key', 'word_rotl', 'word_slice',
            # --- HIGHT-specific exclusions ---
            'get_delta_array_index', 'delta0', 'get_delta_bit_val', 'list_to_byte',
            'rotate_bits_left',
            # --- SKINNY exclusions ---
            'skinny_rounds', 'skinny_sbox_table', 'skinny_sbox_inv_table', 
            'skinny_rc_table', 'skinny_sr_map', 'skinny_sr_inv_map',
            
        }
        
        if func_name in excluded_functions:
            return False
        
        # Family-specific core functions based on actual theory files
        core_functions = {
            'Feistel': [ 
                # SIMON
                'simon_F_function', 'simon_encrypt_round', 'simon_encrypt', 'simon_decrypt',
                'simon_gen_key_schedule_rec', 'simon_generate_key_schedule',
                'simon_encrypt_iterate', 'simon_decrypt_iterate', 
                'simon_encrypt_block', 'simon_decrypt_block', 'simon_decrypt_round_inverse',
                
                # SIMECK
                'simeck_F_function', 'simeck_encrypt_round', 'simeck_decrypt_round_inverse',
                'simeck_gen_key_schedule_rec', 'simeck_generate_key_schedule',
                'simeck_encrypt_iterate', 'simeck_decrypt_iterate',
                'simeck_encrypt_block', 'simeck_decrypt_block',
                
                # XTEA
                'xtea_mix_function', 'xtea_encrypt_round', 'xtea_decrypt_round',
                'xtea_encrypt_iterate', 'xtea_decrypt_iterate',
                'xtea_encrypt_block', 'xtea_decrypt_block', 'xtea_split_key'
            ],
            
            'ARX': [ 
                # SPECK
                'speck_encrypt_round', 'speck_decrypt_round_inverse',
                'speck_encrypt', 'speck_decrypt',
                'speck_gen_key_schedule_rec', 'speck_generate_key_schedule',
                'speck_encrypt_iterate', 'speck_decrypt_iterate',
                'speck_encrypt_block', 'speck_decrypt_block',
                
                # LEA
                'lea_encrypt_round', 'lea_decrypt_round',
                'lea_encrypt', 'lea_decrypt',
                'lea_gen_round_keys_iter', 'lea_generate_round_keys',
                'lea_step_key_expansion', 
                'lea_encrypt_block', 'lea_decrypt_block'
            ],
            
            
            'SPN': [  # PRESENT, GIFT, RECTANGLE, SPARX
                # PRESENT
                'present_round', 'present_encrypt', 'present_decrypt',
                'sbox_layer', 'p_layer', 'key_schedule',
                
                # GIFT
                'gift_encrypt_round', 'gift_decrypt_round',
                'gift_encrypt_block', 'gift_decrypt_block',
                'gift_sbox_layer', 'gift_perm_layer', 
                'gift_add_round_key', 'gift_key_schedule',
   
                # RECTANGLE (Add these!)
                'rectangle_encrypt_round', 
                'rectangle_decrypt_round',
                'rectangle_encrypt_block', 
                'rectangle_decrypt_block',
                'rectangle_sub_column', 
                'rectangle_shift_rows',
                'rectangle_add_round_key',
                'rectangle_generate_all_round_keys',
                'rectangle_encrypt', 
                'rectangle_decrypt'
                
                # SPARX
                'sparx_encrypt_block', 'sparx_decrypt_block',
                'sparx_encrypt_step_iterate', 'sparx_decrypt_step_iterate',
                'sparx_linear_layer', 'sparx_A_perm_16', # Critical: This is the S-box
                'sparx_generate_key_schedule',

                # SKINNY 
                'skinny_encrypt_round', # 'skinny_decrypt_round_inv',
                'skinny_encrypt_iterate', #'skinny_decrypt_iterate',
                'skinny_sub_cells', #'skinny_sub_cells_inv',
                'skinny_add_round_constant', 
                'skinny_shift_rows',# 'skinny_shift_rows_inv',
                'skinny_mix_columns', #'skinny_mix_columns_inv',
                'skinny_gen_keys', 'skinny_tk_update',
                
            ],
            'HIGHT_ARX': [
                # HIGHT (Implementation 1)
                'hight_enc_round', # 'hight_dec_round_inv',
                'hight_encrypt_iterate', # 'hight_decrypt_iterate',
                'hight_initial_trans', 'hight_final_trans',
                'hight_F0', 'hight_F1',
                #'hight_whitening_keys', 'hight_gen_subkeys'
            ]
       
            
        }

        
        
        
        if cipher_family in core_functions:
            return func_name in core_functions[cipher_family]
        
        # Fallback: check if function contains cryptographic operations
        return any(indicator in func_name.lower() for indicator in 
                  ['round', 'encrypt', 'decrypt', 'sbox', 'key', 'schedule'])

    
    @staticmethod
    def _extract_function_body(lines: List[str], start_index: int) -> Tuple[Optional[str], int]:
        """Extract function body until next definition/fun/function or end"""
        body_lines = []
        i = start_index
        
        # Skip the definition line itself
        i += 1
        
        # Look for the equals sign or where clause to find the actual body start
        body_started = False
        while i < len(lines):
            line = lines[i].strip()
            
            # Stop if we hit the next function definition
            if LineByLineFunctionExtractor._is_function_start(line):
                break
            
            # Stop if we hit lemma/theorem/end OR proof tactics for 'function'
            # Stop if we hit any keyword that ends a definition block 
            stop_keywords = [ 'lemma', 'theorem', 'end', 'by pat_completeness', 'termination', 'apply', 'done', 'subsection', 'section' ]
            #stop_keywords = ['lemma', 'theorem', 'end', 'by pat_completeness', 'termination', 'apply', 'done']
            if any(line.startswith(keyword) for keyword in stop_keywords):
                break
            
            # Look for the start of the body (after = or where)
            if not body_started and ('=' in line or 'where' in line):
                body_started = True
            
            if body_started or line:  # Include the line if body started or if it's non-empty
                body_lines.append(line)
            i += 1
        body = '\n'.join(body_lines).strip()
        return body if body else None, i 
        
    @staticmethod
    def _remove_comments(content: str) -> str:
        """Remove comments completely"""
        no_block_comments = re.sub(r'\(\*.*?\*\)', '', content, flags=re.DOTALL)
        no_comments = re.sub(r'--.*$', '', no_block_comments, flags=re.MULTILINE)
        return no_comments



        
class CoreFunctionOperationCounter:
    @staticmethod
    def count_operations_in_core_functions(content: str, cipher_family: str, debug: bool = False) -> Dict[str, int]:
        """Count operations in core functions using proper line-by-line extraction"""
        
        core_counts = CoreFunctionOperationCounter._empty_counts()
        #print('BEF ERRROR')
        # Extract core functions using line-by-line approach
        core_functions, found_functions = LineByLineFunctionExtractor.extract_core_functions(content, cipher_family, debug)
        #print('AFT ERRROR')
        
        if debug:
            print(f"\n=== COUNTING OPERATIONS for {cipher_family} ===")
            print(f"Found functions: {found_functions}")
        
        # Count operations in each core function
        for func_name, func_body in core_functions.items():
            func_counts = CoreFunctionOperationCounter._count_operations_in_text(func_body, cipher_family)
            
            if debug and any(func_counts.values()):
                non_zero_counts = {k: v for k, v in func_counts.items() if v > 0}
                print(f"{func_name}: {non_zero_counts}")
            
            for key in core_counts:
                core_counts[key] += func_counts[key]
        
        if debug:
            print(f"\n=== FINAL COUNTS for {cipher_family} ===")
            for op, count in core_counts.items():
                if count > 0:
                    print(f"{op}: {count}")
        
        return core_counts

    @staticmethod
    def _empty_counts() -> Dict[str, int]: 
        return { 'xor_count': 0, 'rotl_count': 0, 'rotr_count': 0, 'add_count': 0, 'sub_count': 0, 'and_count': 0, 'sbox_count': 0, 'perm_count': 0, 'z_seq_usage': 0, 'uses_shift_params': 0 }

    @staticmethod
    def _count_operations_in_text(text: str, cipher_family: str) -> Dict[str, int]:
        """FIXED: Count operations with family-specific patterns"""
        counts = CoreFunctionOperationCounter._empty_counts()
        
        # Family-specific operation patterns
        if cipher_family == "Feistel":  # Simon, Simeck, XTEA
            patterns = {
                'xor_count': r'\bxor\b',
                # FIXED: XTEA uses push_bit (left shift) and word_rotl
                'rotl_count': r'\b(word_rotl|rotate_bits_left|push_bit)\b', 
                # FIXED: XTEA uses drop_bit (right shift) and word_rotr
                'rotr_count': r'\b(word_rotr|drop_bit)\b',
                'and_count': r'\band\b',
                'add_count': r'\+',  # XTEA uses addition
                'sub_count': r'\-',  # XTEA uses subtraction
                'z_seq_usage': r'\b(z0|z1|z2|z3|z4|get_z_bit_val)\b'
            }

        elif cipher_family == "HIGHT_ARX": 
            # HIGHT uses + (mod 256), -, xor, and specific F-functions
            patterns = { 
                'xor_count': r'\bxor\b', 
                'rotl_count': r'\b(word_rotl|rotate_bits_left)\b', 
                'add_count': r'\+', 
                'sub_count': r'\-', 
                # HIGHT uses a Delta constant array
                'uses_delta_sequence': r'\b(delta0|hight_delta|constant_generation)\b' 
            }
        elif cipher_family == "ARX":  # Speck, LEA, Sparx 
            patterns = {
                'xor_count': r'\bxor\b',
                #  Add lea_rol/lea_ror
                'rotl_count': r'\b(word_rotl|rotate_bits_left|lea_rol)\b',
                'rotr_count': r'\b(word_rotr|rotate_bits_right|lea_ror)\b', 
                'add_count': r'\+',
                'sub_count': r'\-',
                'uses_shift_params': r'\b(get_shift_params|alpha_shift|beta_shift|alpha|beta)\b'
            
            }
        elif cipher_family == "SPN":
            patterns = {
                'xor_count': r'\bxor\b',
                # Matches present_sbox, gift_sbox, rectangle_sub_column, sub_cells
                'sbox_count': r'\b(sbox|sub_column|sub_cells)\b',
                # Matches p_layer, perm_layer, shift_rows, perm_bits
                'perm_count': r'\b(p_layer|perm_|shift_rows|linear_layer)\b',
                
                # SPARX SPECIFICS (It is SPN but uses ARX ops)
                'add_count': r'\+',
                'rotl_count': r'\b(word_rotl|sparx_rol)\b',
                'rotr_count': r'\b(word_rotr|sparx_ror)\b'
            }

        else:
            patterns = {}
        
        for op_type, pattern in patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if op_type in counts:
                counts[op_type] += len(matches)
            else:
                counts[op_type] = len(matches) # This handles new keys like 'uses_delta_sequence'
        
        return counts
   


class UnifiedPDVProcessor:
    """
    Revised Unified PDV Processor.
    Removes arbitrary weighting (e.g., 'crypto_strength_score') to satisfy scientific rigor.
    Generalizes features to support all 11 cipher families (Feistel, ARX, SPN, Hybrid).
    """
    def __init__(self):
        self.feature_names = [
            # 1. Core Parameters (Universal)
            'block_size', 'key_size', 'rounds',
            
            # 2. Family Indicators (One-Hot)
            'is_feistel', 'is_arx', 'is_spn', 'is_hybrid', # Added Hybrid for Sparx/HIGHT
            
            # 3. Structural Topology (CRITICAL for Zero-Shot)
            'branch_count',       # 2 (Feistel), 4 (Sparx/Rectangle), 8 (HIGHT)
            'sbox_type',          # 0=None, 1=LUT (Present), 2=ARX-box (Sparx)
            'permutation_type',   # 0=None, 1=Bitwise (Present), 2=ShiftRows (Skinny/AES)
            
            # 4. Operation Counts (Raw Data - Let GNN learn weights)
            'xor_count', 'rotl_count', 'rotr_count', 
            'add_count', 'sub_count', 'and_count', 
            'sbox_count', 'perm_count',
            
            # 5. Densities (Normalized metrics - comparable across sizes)
            'nonlinearity_density',  # (Sbox + And + Add) / Rounds
            'diffusion_density',     # (Rot + Perm) / Rounds
            'state_update_density',  # Total Ops / Rounds
            
            # 6. Graph Statistics (From AST)
            'ast_node_count', 'ast_edge_count', 'function_count',
            'cyclomatic_complexity_proxy', # edges/nodes ratio
            
            # 7. Key Schedule Characteristics
            'key_schedule_type', # 0=None, 1=Simple (Perm/Rot), 2=Complex (Sbox/Feistel)
            'key_injection_type', # 0=XOR, 1=ADD
            
            'algebraic_degree_proxy',
            'key_state_ratio',
            'sbox_density',
            'avg_degree_centrality',
            'critical_path_proxy',
            'interaction_density',
            
            
            
        ]
    
    def create_unified_pdv(self, extracted_pdv: Dict, ast_data: Dict) -> Dict[str, Any]:
        """Creates a standardized feature vector from extracted data."""
        try:
            # 1. Basic Info
            cipher_family = extracted_pdv.get("cipher_family", "").lower()
            cipher_name = extracted_pdv.get("cipher_name", "").lower()
            ops = extracted_pdv.get("ops_summary", {})
            # Safely get rounds, defaulting to 1 to avoid division by zero
            rounds = self._safe_get(extracted_pdv, "rounds", 1)
            if rounds == 0: rounds = 1 
            
            # 2. Determine Structure Features (The "Zero-Shot" helpers)
            # Default to 2 branches (standard for Feistel/ARX like Simon/Speck)
            branch_count = 2 
            if "hight" in cipher_name:
                branch_count = 8
            elif "sparx" in cipher_name or "rectangle" in cipher_name or "skinny" in cipher_name:
                branch_count = 4
            
            # 3. Determine Component Types
            sbox_type = 0
            if ops.get("sbox_count", 0) > 0:
                # Distinguish standard S-box (1) from ARX-box or other types if needed
                # For now, 1 = Has S-box is sufficient signal
                sbox_type = 1 
            
            # 4. Calculate Densities (Scientific, not arbitrary weights)
            # Nonlinear ops: Sbox, AND, Modular Add
            nonlinear_ops = ops.get('sbox_count', 0) + ops.get('and_count', 0) + ops.get('add_count', 0)
            
            # Diffusion ops: Rotations, Permutations
            diffusion_ops = ops.get('rotl_count', 0) + ops.get('rotr_count', 0) + ops.get('perm_count', 0)
            
            total_ops = sum(ops.values())
            
            # Family Classification Logic
            is_feistel = 1 if "feistel" in cipher_family else 0
            is_arx = 1 if "arx" in cipher_family else 0
            is_spn = 1 if "spn" in cipher_family else 0
            is_hybrid = 1 if ("sparx" in cipher_family or "hight" in cipher_family) else 0

            # 5. Graph Stats
            node_count = len(ast_data.get("nodes", []))
            edge_count = len(ast_data.get("edges", []))
            func_count = len(ast_data.get("functions", []))
            complexity_proxy = edge_count / max(node_count, 1)

            ### ADDITIONAL METRICS
            # 1. Algebraic Degree Proxy (AND/OR/MUL increase degree more than XOR/ADD)
            # MUL/AND are non-linear in GF(2). ADD is non-linear in Z_{2^n}.
            degree_ops = ops.get('and_count', 0) + ops.get('or_count', 0) + ops.get('mul_count', 0)
            # Add partial weight for modular addition
            degree_ops += (ops.get('add_count', 0) * 0.5) 
            algebraic_degree_proxy = degree_ops / max(total_ops, 1)

            # 2. Key vs State Balance
            # Ratio of Key Size to Block Size (e.g. 128/64 = 2.0)
            b_size = self._safe_get(extracted_pdv, "block_size", 64)
            k_size = self._safe_get(extracted_pdv, "key_size", 128)
            key_state_ratio = k_size / max(b_size, 1)

            # 3. S-box Density (Active S-boxes per block bit)
            # PRESENT: 16 S-boxes / 64 bits = 0.25
            # SKINNY: 16 S-boxes / 64 bits = 0.25
            # Sparx: 0 (uses ARX box)
            sbox_density = ops.get('sbox_count', 0) / max(b_size, 1)

            # 4. Average Degree (Connectivity)
            # 2 * Edges / Nodes. Higher = denser graph connection.
            avg_degree = (2.0 * edge_count) / max(node_count, 1)

            # 5. Critical Path Proxy (Depth)
            # Approximates logic depth: Nodes / Parallel Branches
            # Simon (2 branches): 186 / 2 = 93 depth
            # HIGHT (8 branches): 150 / 8 = 18 depth
            critical_path_proxy = node_count / max(branch_count, 1)
            
            # 6. Interaction Density
            # Ratio of Binary Ops (XOR/ADD/AND) to Total Nodes
            # Higher = more mixing of variables.
            binary_ops = ops.get('xor_count', 0) + ops.get('add_count', 0) + ops.get('and_count', 0)
            interaction_density = binary_ops / max(node_count, 1)

            features = {
                # Core
                'block_size': self._safe_get(extracted_pdv, "block_size", 64),
                'key_size': self._safe_get(extracted_pdv, "key_size", 128),
                'rounds': rounds,
                
                # Families
                'is_feistel': is_feistel,
                'is_arx': is_arx,
                'is_spn': is_spn,
                'is_hybrid': is_hybrid,
                
                # Structure
                'branch_count': branch_count,
                'sbox_type': sbox_type,
                'permutation_type': 1 if ops.get("perm_count", 0) > 0 else 0,
                
                # Raw Counts
                'xor_count': ops.get('xor_count', 0),
                'rotl_count': ops.get('rotl_count', 0),
                'rotr_count': ops.get('rotr_count', 0),
                'add_count': ops.get('add_count', 0),
                'sub_count': ops.get('sub_count', 0),
                'and_count': ops.get('and_count', 0),
                'sbox_count': ops.get('sbox_count', 0),
                'perm_count': ops.get('perm_count', 0),
                
                # Densities (Normalization allows comparing HIGHT vs Simon)
                'nonlinearity_density': nonlinear_ops / max(rounds, 1),
                'diffusion_density': diffusion_ops / max(rounds, 1),
                'state_update_density': total_ops / max(rounds, 1),
                
                # Graph Stats
                'ast_node_count': node_count,
                'ast_edge_count': edge_count,
                'function_count': func_count,
                'cyclomatic_complexity_proxy': complexity_proxy,
                
                # Key Schedule (Simplified)
                'key_schedule_type': self._determine_ks_type(extracted_pdv),
                'key_injection_type': 1 if ("arx" in cipher_family or "add_count" in ops) else 0, # 1=Add, 0=XOR

                'algebraic_degree_proxy': algebraic_degree_proxy,
                'key_state_ratio': key_state_ratio,
                'sbox_density': sbox_density,
                'avg_degree_centrality': avg_degree,
                'critical_path_proxy': critical_path_proxy,
                'interaction_density': interaction_density,
            
            }
            
            return self._ensure_feature_completeness(features)
            
        except Exception as e:
            print(f"Error creating Unified PDV: {e}")
            # Return zeroed vector on error
            return {f: 0 for f in self.feature_names}

    def _determine_ks_type(self, pdv):
        """
        Heuristic for key schedule complexity.
        1 = Simple (Permutations/Rotations only - e.g. Simon, Present)
        2 = Complex (S-boxes, Feistel steps, or heavy generation - e.g. Speck, Skinny)
        """
        fam = pdv.get("cipher_family", "").lower()
        name = pdv.get("cipher_name", "").lower()
        
        # Speck, Skinny, HIGHT have heavier key schedules
        if "skinny" in name or "hight" in name or "speck" in name:
            return 2 
        # Simon, Present, Rectangle are relatively simple/linear
        return 1 

    def _safe_get(self, d, k, default):
        """Safely get value from dictionary."""
        val = d.get(k)
        return val if val is not None else default

    def _ensure_feature_completeness(self, features):
        """Ensure all defined feature names exist in the output dict."""
        for f in self.feature_names:
            if f not in features:
                features[f] = 0.0
        return features
        

# ----------------------------
# FIXED ExpressionParser: Robust parsing for ALL cipher families
# ----------------------------
class ExpressionParser:
    @staticmethod
    def parse_expr_improved(expr: str) -> Dict[str, Any]:
        """REWRITTEN: Robust parser for complex Isabelle expressions"""
        e = expr.strip()
        
        # Remove trailing semicolons
        if e.endswith(';'):
            e = e[:-1].strip()

        # Handle surrounding parentheses (balanced)
        while e.startswith('(') and e.endswith(')'):
            depth = 0
            valid = True
            for i, ch in enumerate(e):
                if ch == '(': depth += 1
                elif ch == ')': depth -= 1
                if depth == 0 and i < len(e) - 1:
                    valid = False
                    break
            if not valid: break
            e = e[1:-1].strip()

        # LET expressions
        if e.startswith('let'):
            let_match = re.match(r'let\s+(.*?)\s+in\s+(.*)$', e, re.DOTALL)
            if let_match:
                bindings_raw, body_raw = let_match.group(1).strip(), let_match.group(2).strip()
                bindings = ExpressionParser.parse_bindings(bindings_raw)
                body = ExpressionParser.parse_expr_improved(body_raw)
                return {"op": "LET", "bindings": bindings, "body": body}

        # IF expressions
        if e.startswith('if '):
            depth = 0
            then_pos = else_pos = -1
            for i, char in enumerate(e):
                if char in '([{': depth += 1
                elif char in ')]}': depth -= 1
                elif depth == 0:
                    if then_pos == -1 and e[i:i+4] == 'then':
                        then_pos = i
                    elif else_pos == -1 and e[i:i+4] == 'else':
                        else_pos = i
            if then_pos != -1 and else_pos != -1:
                condition = e[2:then_pos].strip()
                then_branch = e[then_pos+4:else_pos].strip()
                else_branch = e[else_pos+4:].strip()
                return {
                    "op": "IF", 
                    "condition": ExpressionParser.parse_expr_improved(condition),
                    "then": ExpressionParser.parse_expr_improved(then_branch),
                    "else": ExpressionParser.parse_expr_improved(else_branch)
                }

        # CRITICAL FIX: Handle rotation operations FIRST before general function application
        rotation_match = ExpressionParser._match_rotation_operation(e)
        if rotation_match:
            return rotation_match

        # Handle mathematical operations
        operators = [
            (r'=', 'EQ'), (r'<', 'LT'), (r'>', 'GT'),
            (r'\+', 'ADD'), (r'-', 'SUB'), 
            (r'\*', 'MUL'), (r'\bdiv\b', 'DIV'), (r'\bmod\b', 'MOD'),
            (r'∧', 'AND')
        ]
        
        for op_pattern, op_name in operators:
            depth = 0
            for i in range(len(e)-1, -1, -1):
                if e[i] in ')]}': depth += 1
                elif e[i] in '([{': depth -= 1
                elif depth == 0:
                    substr = e[i:]
                    match = re.match(op_pattern, substr)
                    if match:
                        op_len = len(match.group(0))
                        left = e[:i].strip()
                        right = e[i+op_len:].strip()
                        if left and right:
                            return {
                                "op": op_name,
                                "left": ExpressionParser.parse_expr_improved(left),
                                "right": ExpressionParser.parse_expr_improved(right)
                            }

        # Handle function applications (space-separated Isabelle style)
        # Use improved tokenization that respects parentheses
        tokens = ExpressionParser.tokenize_respecting_parentheses(e)
        if len(tokens) > 1:
            func = tokens[0]
            args = tokens[1:]
            parsed_args = [ExpressionParser.parse_expr_improved(arg) for arg in args]
            
            func_lower = func.lower()
            
            # Bitwise operations
            if func_lower in ('xor', 'and', 'or'):
                return {"op": func_lower.upper(), "args": parsed_args}
            
            # Tuple operations
            elif func_lower in ('fst', 'snd'):
                if parsed_args:
                    return {"op": func_lower.upper(), "arg": parsed_args[0]}
            
            # List operations
            elif func_lower in ('take', 'drop', 'tl', 'hd', 'rev'):
                return {"op": "LIST_" + func_lower.upper(), "args": parsed_args}
            
            # Special functions
            elif func_lower == 'f':
                return {"op": "F_FUNCTION", "args": parsed_args}
            
            # Generic function application
            return {"op": "APPLY", "func": func, "args": parsed_args}

        # Handle list operations
        if '!' in e and '!=' not in e:
            parts = e.split('!', 1)
            if len(parts) == 2:
                return {
                    "op": "LIST_INDEX",
                    "list": ExpressionParser.parse_expr_improved(parts[0].strip()),
                    "index": ExpressionParser.parse_expr_improved(parts[1].strip())
                }
        
        if '@' in e:
            parts = e.split('@', 1)
            if len(parts) == 2:
                return {
                    "op": "LIST_CONCAT",
                    "left": ExpressionParser.parse_expr_improved(parts[0].strip()),
                    "right": ExpressionParser.parse_expr_improved(parts[1].strip())
                }

        # Handle literals
        if e.isdigit():
            return {"literal": int(e)}
        elif e.startswith('0x'):
            try:
                return {"literal": int(e, 16)}
            except ValueError:
                pass
        elif e.startswith('0b'):
            try:
                return {"literal": int(e[2:], 2)}
            except ValueError:
                pass
        elif e.startswith('"') and e.endswith('"'):
            return {"string": e[1:-1]}

        # Fallback: variable or unparsed expression
        return {"var": e}

    @staticmethod
    def _match_rotation_operation(expr: str) -> Optional[Dict[str, Any]]:
        """CRITICAL FIX: Detect rotation operations in complex expressions"""
        # Pattern 1: Simple rotations - word_rotl amount arg
        simple_rot_match = re.match(
            r'^\s*(word_rotl|word_rotr|rotl|rotr)\s+(\S+)\s+(.+)$', 
            expr, re.IGNORECASE
        )
        if simple_rot_match:
            func = simple_rot_match.group(1).lower()
            amount = simple_rot_match.group(2).strip()
            arg = simple_rot_match.group(3).strip()
            
            op_type = "ROTL" if "rotl" in func else "ROTR"
            return {
                "op": op_type,
                "amount": ExpressionParser.parse_expr_improved(amount),
                "arg": ExpressionParser.parse_expr_improved(arg)
            }
        
        # Pattern 2: Rotations with parenthesized arguments - word_rotl amount (complex expr)
        paren_rot_match = re.match(
            r'^\s*(word_rotl|word_rotr|rotl|rotr)\s+(\S+)\s*\((.*)\)\s*$', 
            expr, re.IGNORECASE | re.DOTALL
        )
        if paren_rot_match:
            func = paren_rot_match.group(1).lower()
            amount = paren_rot_match.group(2).strip()
            arg = f"({paren_rot_match.group(3).strip()})"  # Keep parentheses for parsing
            
            op_type = "ROTL" if "rotl" in func else "ROTR"
            return {
                "op": op_type,
                "amount": ExpressionParser.parse_expr_improved(amount),
                "arg": ExpressionParser.parse_expr_improved(arg)
            }
        
        # Pattern 3: Deep search for rotation keywords anywhere in expression
        if re.search(r'\b(word_rotl|word_rotr|rotl|rotr)\b', expr, re.IGNORECASE):
            # Try to extract rotation operation from complex expression
            tokens = expr.split()
            for i, token in enumerate(tokens):
                token_lower = token.lower()
                if token_lower in ('word_rotl', 'word_rotr', 'rotl', 'rotr') and i + 1 < len(tokens):
                    # Found rotation keyword, try to parse amount and argument
                    amount = tokens[i + 1]
                    # The argument is everything after the amount
                    arg_tokens = tokens[i + 2:]
                    if arg_tokens:
                        arg = ' '.join(arg_tokens)
                        op_type = "ROTL" if "rotl" in token_lower else "ROTR"
                        return {
                            "op": op_type,
                            "amount": ExpressionParser.parse_expr_improved(amount),
                            "arg": ExpressionParser.parse_expr_improved(arg)
                        }
        
        return None

    @staticmethod
    def tokenize_respecting_parentheses(expr: str) -> List[str]:
        """IMPROVED: Tokenize while keeping parenthesized expressions together"""
        tokens = []
        current = []
        depth = 0
        
        i = 0
        while i < len(expr):
            char = expr[i]
            
            if char == '(':
                if depth == 0 and current:
                    # Save current token before starting parentheses
                    token = ''.join(current).strip()
                    if token:
                        tokens.append(token)
                    current = []
                depth += 1
                current.append(char)
            elif char == ')':
                depth -= 1
                current.append(char)
                if depth == 0:
                    # Finished parenthesized expression
                    token = ''.join(current).strip()
                    if token:
                        tokens.append(token)
                    current = []
            elif char == ' ' and depth == 0:
                if current:
                    token = ''.join(current).strip()
                    if token:
                        tokens.append(token)
                    current = []
            else:
                current.append(char)
            
            i += 1
        
        # Don't forget the last token
        if current:
            token = ''.join(current).strip()
            if token:
                tokens.append(token)
        
        return tokens

    @staticmethod
    def parse_bindings(bindings_str: str) -> Dict[str, Any]:
        """Parse let-bindings with pattern matching."""
        bindings = {}
        parts = [p.strip() for p in re.split(r'[;\n]', bindings_str) if p.strip()]
        for part in parts:
            if '=' in part:
                left, right = part.split('=', 1)
                bindings[left.strip()] = ExpressionParser.parse_expr_improved(right.strip())
        return bindings

  
# ----------------------------
# FIXED: Enhanced extractor classes with consistent operation counting
# ----------------------------
class CipherExtractor(ABC):
    
    def __init__(self, thy_path: str, profile: Dict[str, Any]):
        self.thy_path = thy_path
        self.profile = profile
        raw_content = self._read_file(thy_path)
        
        # === APPLY CONSTANT PROPAGATION ===
        self.content = inline_constants(raw_content)
        
        #self.content = self._read_file(thy_path)
        
        family = CIPHER_PROFILES.get(self.profile, {}).get("family", "")
        all_funcs, _ = LineByLineFunctionExtractor.extract_core_functions(self.content, family, debug=False)

        self.definitions = list(all_funcs.items())

        self.nodes: List[Dict] = []
        self.edges: List[Dict] = []
        self.functions: List[str] = []
        self.pdv: Dict[str, Any] = {}


    def _read_file(self, path: str) -> str:
        with open(path, 'r', encoding='utf-8') as f:
            return f.read()

    @abstractmethod
    def extract(self) -> Dict[str, Any]:
        pass

    def _variants_from_filename(self, filename: str) -> Optional[Tuple[int, int]]:
        m = re.search(r'(\d+)_(\d+)', filename)
        if not m:
            return None
        return int(m.group(1)), int(m.group(2))

    def _count_operations_core_functions(self, debug: bool = False) -> Dict[str, int]:
        """Count operations only in core cryptographic functions"""
        return CoreFunctionOperationCounter.count_operations_in_core_functions(
            self.content, self._get_cipher_family(), debug
        )
    
    def _get_cipher_family(self) -> str:
        """Determine cipher family from profile"""
        profile_info = CIPHER_PROFILES.get(self.profile, {})
        return profile_info.get("family", "")

    # Keep the old method for reference (optional)
    def _count_operations_from_ast(self) -> Dict[str, int]:
        """Original AST-based counting"""
        op_counts = self._empty_counts()
        
        for func_name, body in self.definitions:
            m = re.search(r'=\s*(.*)', body, re.DOTALL)
            rhs = m.group(1).strip() if m else body.strip()
            try:
                ast_tree = ExpressionParser.parse_expr_improved(rhs)
                func_counts = count_operations_in_ast(ast_tree)
                for key in op_counts:
                    op_counts[key] += func_counts.get(key, 0)
            except Exception:
                continue
        
        return op_counts
    
    def _empty_counts(self) -> Dict[str, int]:
        return {
            'xor_count': 0, 'rotl_count': 0, 'rotr_count': 0,
            'add_count': 0, 'sub_count': 0, 'and_count': 0,
            'sbox_count': 0, 'perm_count': 0, 'z_seq_usage': 0
        }

        ####
        
# =============================================================================
# ENHANCED AST EXTRACTION WITH CRYPTOGRAPHIC SEMANTICS
# =============================================================================
def ast_to_nodes_edges_cryptographic(ast: Dict[str, Any], base_id: int = 0, 
                                   context: str = "global", cipher_family: str = "") -> Tuple[List[Dict], List[Dict], int]:
    """FIXED: Enhanced AST extraction with working cryptographic semantics"""
    
    nodes: List[Dict] = []
    edges: List[Dict] = []
    cur_id = base_id

    def determine_cryptographic_semantics(node: Dict[str, Any], parent_context: str, 
                                        cipher_family: str) -> Dict[str, Any]:
        """FIXED: Working cryptographic role assignment"""
        
        op = (node.get("op") or "").lower()
        node_label = node.get("label", "")
        
        semantics = {
            "crypto_role": "operation",
            "crypto_strength": 1.0,
            "diffusion_power": 0.0,
            "nonlinearity": 0.0,
            "data_flow_role": "processing"
        }
        
        # Operation-specific cryptographic properties
        crypto_ops = {
            "xor": {"crypto_role": "linear_mixing", "crypto_strength": 1.0, "nonlinearity": 0.0},
            "and": {"crypto_role": "nonlinear_mixing", "crypto_strength": 3.0, "nonlinearity": 3.0},
            "rotl": {"crypto_role": "diffusion", "diffusion_power": 2.0, "crypto_strength": 1.5},
            "rotr": {"crypto_role": "diffusion", "diffusion_power": 2.0, "crypto_strength": 1.5},
            "add": {"crypto_role": "modular_operation", "crypto_strength": 2.5, "nonlinearity": 2.0},
            "sub": {"crypto_role": "modular_operation", "crypto_strength": 2.5, "nonlinearity": 2.0},
        }
        
        if op in crypto_ops:
            semantics.update(crypto_ops[op])
        
        # Family-specific enhancements
        if cipher_family == "Feistel":
            if "f_function" in str(node_label).lower():
                semantics.update({
                    "crypto_role": "feistel_f_function",
                    "crypto_strength": 4.0,
                    "nonlinearity": 3.0,
                    "data_flow_role": "nonlinear_layer"
                })
                
        elif cipher_family == "ARX":
            if op == "add":
                semantics.update({
                    "crypto_role": "modular_addition", 
                    "crypto_strength": 3.0,
                    "nonlinearity": 2.5
                })
                
        elif cipher_family == "SPN":
            if "sbox" in str(node_label).lower():
                semantics.update({
                    "crypto_role": "sbox_substitution",
                    "crypto_strength": 5.0,
                    "nonlinearity": 4.0,
                    "data_flow_role": "confusion"
                })
            elif "p_layer" in str(node_label).lower():
                semantics.update({
                    "crypto_role": "permutation_layer", 
                    "diffusion_power": 4.0,
                    "data_flow_role": "diffusion"
                })
            
        return semantics


    def walk_cryptographic(node: Dict[str, Any], parent_id: Optional[int] = None, 
                         node_context: str = "operation") -> int:
        nonlocal cur_id, nodes, edges
        
        nid = cur_id
        cur_id += 1

        # Get cryptographic semantics for this node
        crypto_semantics = determine_cryptographic_semantics(node, node_context, cipher_family)
        
        # Create enriched node
        node_data = {
            "id": nid,
            "type": "op" if 'op' in node else "var" if 'var' in node else "literal",
            "label": node.get("op") or node.get("var") or str(node.get("literal", "")),
            "context": node_context,
            **crypto_semantics  # Add all cryptographic semantics
        }
        
        # Add literal value if present
        if 'literal' in node:
            node_data["value"] = node['literal']
            node_data["value_type"] = "numeric"
        elif 'string' in node:
            node_data["value"] = node['string'] 
            node_data["value_type"] = "string"
        
        nodes.append(node_data)

        # Process children with basic edges first
        if parent_id is not None:
            edges.append({"source": parent_id, "target": nid, "type": "child"})

        # Handle different node types
        if 'op' in node:
            if node["op"] in ("ROTL", "ROTR"):
                if "amount" in node:
                    amount_id = walk_cryptographic(node["amount"], nid, "rotation_amount")
                    edges.append({"source": nid, "target": amount_id, "type": "amount"})
                if "arg" in node:
                    arg_id = walk_cryptographic(node["arg"], nid, "rotation_arg")
                    edges.append({"source": nid, "target": arg_id, "type": "arg"})
                    
            elif node["op"] in ("FST", "SND"):
                if "arg" in node:
                    arg_id = walk_cryptographic(node["arg"], nid, f"{node['op'].lower()}_arg")
                    edges.append({"source": nid, "target": arg_id, "type": "arg"})
            
            elif node["op"] == "APPLY":
                # In walk_cryptographic, inside elif node["op"] == "APPLY":
                if "func" in node:
                    # === OLD BUGGY CODE ===
                    # func_id = walk_cryptographic({"var": node["func"]}, nid, "function_name")
                    # edges.append({"source": nid, "target": func_id, "type": "func"})
                    
                    # === NEW FIXED CODE ===
                    func_id = cur_id
                    cur_id += 1
                    
                    # 1. Create a node for the function name
                    func_node_data = {
                        "id": func_id,
                        "type": "func_name",
                        "label": node["func"],
                        "context": "apply_func"  # More specific context
                    }
                    
                    # 2. *** Apply cryptographic semantics TO THE FUNCTION NAME ***
                    func_semantics = determine_cryptographic_semantics(func_node_data, node_context, cipher_family)
                    func_node_data.update(func_semantics)
                    
                    # 3. Add the enriched node
                    nodes.append(func_node_data)
                    edges.append({"source": nid, "target": func_id, "type": "func"})
                    # ========================
                
                if "args" in node:
                    for pos, arg in enumerate(node["args"]):
                        child_id = walk_cryptographic(arg, nid, "apply_arg")
                        edges.append({"source": nid, "target": child_id, "type": "arg", "position": pos})
            
            elif node["op"] == "LET":
                if "bindings" in node:
                    for var_name, expr in node["bindings"].items():
                        binding_id = walk_cryptographic(expr, nid, f"binding_{var_name}")
                        edges.append({"source": nid, "target": binding_id, "type": "binding", "var": var_name})
                if "body" in node:
                    body_id = walk_cryptographic(node["body"], nid, "let_body")
                    edges.append({"source": nid, "target": body_id, "type": "body"})
            
            elif node["op"] == "IF":
                if "condition" in node:
                    cond_id = walk_cryptographic(node["condition"], nid, "condition")
                    edges.append({"source": nid, "target": cond_id, "type": "condition"})
                if "then" in node:
                    then_id = walk_cryptographic(node["then"], nid, "then_branch")
                    edges.append({"source": nid, "target": then_id, "type": "then"})
                if "else" in node:
                    else_id = walk_cryptographic(node["else"], nid, "else_branch")
                    edges.append({"source": nid, "target": else_id, "type": "else"})
            
            # Handle binary operations
            elif "left" in node and "right" in node:
                left_id = walk_cryptographic(node["left"], nid, "left_operand")
                edges.append({"source": nid, "target": left_id, "type": "left"})
                right_id = walk_cryptographic(node["right"], nid, "right_operand")
                edges.append({"source": nid, "target": right_id, "type": "right"})
            
            # Handle generic args list
            elif "args" in node:
                for pos, arg in enumerate(node["args"]):
                    if isinstance(arg, dict):
                        child_id = walk_cryptographic(arg, nid, f"{node['op']}_arg")
                        edges.append({"source": nid, "target": child_id, "type": "arg", "position": pos})
                
        # Handle variables - try to re-parse complex expressions
        elif 'var' in node:
            var_value = node["var"]
            # Try to re-parse complex expressions that weren't parsed
            if any(op in var_value for op in [' ', '(', ')', '=', '+', '-', '*', '/']):
                try:
                    reparsed = ExpressionParser.parse_expr_improved(var_value)
                    if 'var' not in reparsed or reparsed['var'] != var_value:
                        return walk_cryptographic(reparsed, parent_id, node_context)
                except:
                    pass  # Keep as variable if parsing fails
                
        return nid

    root_id = walk_cryptographic(ast, None, context)
    return nodes, edges, cur_id

# =============================================================================
# DETECT CRYPTOGRAPHIC PATTERNS IN AST
# =============================================================================

def detect_cryptographic_patterns(nodes: List[Dict], edges: List[Dict], cipher_family: str) -> Dict[str, Any]:
    """Detect high-level cryptographic patterns in the AST"""
    
    patterns = {
        "feistel_network": False,
        "arx_operation_chains": [],
        "spn_layers": False,
        "key_schedule_complexity": 0,
        "round_function_structure": {},
        "cryptographic_operation_distribution": {}
    }
    
    if not nodes:
        return patterns

    # Convert to node lookup for easier traversal
    node_dict = {node["id"]: node for node in nodes}
    
    # Count cryptographic roles
    crypto_roles = {}
    for node in nodes:
        role = node.get("crypto_role", "unknown")
        crypto_roles[role] = crypto_roles.get(role, 0) + 1
    
    patterns["cryptographic_operation_distribution"] = crypto_roles

    if cipher_family == "Feistel":
        patterns.update(detect_feistel_patterns(nodes, edges, node_dict))
    elif cipher_family == "ARX":
        patterns.update(detect_arx_patterns(nodes, edges, node_dict))
    elif cipher_family == "SPN":
        patterns.update(detect_spn_patterns(nodes, edges, node_dict))
    
    return patterns

def detect_feistel_patterns(nodes: List[Dict], edges: List[Dict], node_dict: Dict) -> Dict[str, Any]:
    """FIXED: Detect Feistel network by looking at the APPLY node's PARENT"""
    patterns = {}
    
    # 1. Find F-function applications (the func_name nodes)
    f_functions = [n for n in nodes if n.get("crypto_role") == "feistel_f_function"]
    
    round_structures = []
    for f_func in f_functions:
        # 2. Find the parent APPLY node that *calls* this F-function
        apply_node_id = None
        for edge in edges:
            if edge["target"] == f_func["id"] and edge.get("type") == "func":
                apply_node_id = edge["source"]
                break
        
        if not apply_node_id:
            continue

        # 3. Find the PARENT node of the APPLY node (i.e., where the output goes)
        parent_xor_node_id = None
        for edge in edges:
            if edge["target"] == apply_node_id and edge.get("type") in ["arg", "child"]:
                parent_xor_node_id = edge["source"]
                break

        if not parent_xor_node_id:
            continue
            
        # 4. Check if this parent node is an XOR
        target_node = node_dict.get(parent_xor_node_id)
        if target_node and target_node.get("label") == "XOR":
            round_structures.append({
                "f_function_apply_node": apply_node_id,
                "mixing_operation": target_node["id"],
            })
    
    patterns["feistel_rounds_detected"] = len(round_structures)
    patterns["round_structures"] = round_structures
    patterns["feistel_network"] = len(round_structures) > 0
    
    return patterns
    
    

def detect_arx_patterns(nodes: List[Dict], edges: List[Dict], node_dict: Dict) -> Dict[str, Any]:
    """FIXED: Detect ARX chains by resolving LET-bindings"""
    patterns = {}
    arx_chains = []

    # 1. Create a map of where variables are defined
    #    variable_map = {"var_name": node_id_of_definition}
    variable_map = {}
    let_nodes = [n for n in nodes if n.get("label") == "LET"]
    for let_node in let_nodes:
        # Find all binding edges from this LET node
        binding_edges = [e for e in edges if e["source"] == let_node["id"] and e.get("type") == "binding"]
        for edge in binding_edges:
            var_name = edge.get("var")
            def_node_id = edge.get("target")
            if var_name:
                # Map the simple variable name (e.g., "rs_x") to the node that defines it (e.g., node 1)
                variable_map[var_name] = def_node_id

    # 2. Now, find all ADD operations
    add_ops = [n for n in nodes if n.get("label") == "ADD"]
    
    for add_op in add_ops:
        found_rot_input = False
        found_xor_output = False

        # 3. Check the INPUTS to the ADD node
        input_edges = [e for e in edges if e["source"] == add_op["id"] and e.get("type") in ["left", "right", "arg"]]
        for in_edge in input_edges:
            input_node = node_dict.get(in_edge["target"])
            if not input_node:
                continue

            # Check if the input is a variable defined in our map
            if input_node["type"] == "var" and input_node["label"] in variable_map:
                # It's a variable! Find its *real* source.
                real_source_node_id = variable_map[input_node["label"]]
                real_source_node = node_dict.get(real_source_node_id)
                
                if real_source_node and real_source_node.get("label") in ["ROTL", "ROTR"]:
                    found_rot_input = True
                    break
            # Check if the input is just a direct rotation
            elif input_node.get("label") in ["ROTL", "ROTR"]:
                found_rot_input = True
                break
        
        if not found_rot_input:
            continue

        # 4. Check the OUTPUTS of the ADD node
        # We need to find the variable this ADD is bound to
        add_binding_var = None
        for var_name, def_node_id in variable_map.items():
            if def_node_id == add_op["id"]:
                add_binding_var = var_name
                break
        
        if not add_binding_var:
            continue # This ADD isn't bound to a var, logic fails

        # Find all nodes that *use* this variable
        for node in nodes:
            # We are looking for an XOR that uses this variable
            if node.get("label") != "XOR":
                continue

            # Check the inputs of this XOR node
            xor_input_edges = [e for e in edges if e["source"] == node["id"] and e.get("type") in ["left", "right", "arg"]]
            for xor_edge in xor_input_edges:
                xor_input_node = node_dict.get(xor_edge["target"])
                if xor_input_node and xor_input_node["type"] == "var" and xor_input_node["label"] == add_binding_var:
                    found_xor_output = True
                    arx_chains.append({
                        "add_op": add_op["id"],
                        "rotation_op_source": "resolved_from_var",
                        "xor_op": node["id"],
                        "chain_length": 3
                    })
                    break
            if found_xor_output:
                break
    
    patterns["arx_operation_chains"] = arx_chains
    patterns["arx_chain_density"] = len(arx_chains) / max(len(nodes), 1)
    
    return patterns


def detect_spn_patterns(nodes: List[Dict], edges: List[Dict], node_dict: Dict) -> Dict[str, Any]:
    """FIXED: Detect SPN layer patterns by looking at the APPLY node's PARENT"""
    patterns = {}
    
    # 1. Find S-box applications (the func_name nodes)
    sbox_ops = [n for n in nodes if n.get("crypto_role") == "sbox_substitution"]
    
    sbox_perm_chains = []
    for sbox_op in sbox_ops:
        # 2. Find the parent APPLY node that *calls* this S-box function
        apply_node_id = None
        for edge in edges:
            if edge["target"] == sbox_op["id"] and edge.get("type") == "func":
                apply_node_id = edge["source"]
                break
        
        if not apply_node_id:
            continue

        # 3. Find the PARENT node of the S-Box APPLY node (this should be the P-Layer APPLY node)
        parent_player_node_id = None
        for edge in edges:
             if edge["target"] == apply_node_id and edge.get("type") in ["arg", "child"]:
                parent_player_node_id = edge["source"]
                break
        
        if not parent_player_node_id:
            continue

        # 4. Check if this parent node is a P-Layer
        target_node = node_dict.get(parent_player_node_id)
        
        is_p_layer = False
        if target_node and target_node.get("crypto_role") == "permutation_layer":
            # Parent is the P-layer function node itself (e.g. p_layer_bitwise)
            is_p_layer = True
        elif target_node and target_node.get("label") == "APPLY":
            # Parent is an APPLY node, check if IT calls a P-layer function
            for edge in edges:
                if edge["source"] == target_node["id"] and edge.get("type") == "func":
                    func_node = node_dict.get(edge["target"])
                    if func_node and func_node.get("crypto_role") == "permutation_layer":
                        is_p_layer = True
                        break

        if is_p_layer:
            sbox_perm_chains.append({
                "sbox_apply_node": apply_node_id,
                "perm_apply_node": target_node["id"],
                "chain_length": 2
            })
    
    patterns["sbox_perm_chains"] = sbox_perm_chains
    patterns["spn_layers"] = len(sbox_perm_chains) > 0
    
    return patterns


# =============================================================================
# ENHANCED FEISTEL EXTRACTOR WITH CRYPTOGRAPHIC DEPTH
# =============================================================================

class FeistelExtractor(CipherExtractor):
    def _count_feistel_operations(self, debug: bool = False) -> Dict[str, int]:
        # Use the corrected operation counter
        core_counts = CoreFunctionOperationCounter.count_operations_in_core_functions(
            self.content, self._get_cipher_family(), debug
        )
        
        # CHECK IF THIS IS SIMON OR SIMECK (Bitwise only)
        if "simon" in self.profile.lower() or "simeck" in self.profile.lower():
            core_counts['add_count'] = 0    
            core_counts['sub_count'] = 0     
            core_counts['sbox_count'] = 0   
            core_counts['perm_count'] = 0   

        # CHECK IF THIS IS XTEA (Uses Addition/Subtraction)
        elif "xtea" in self.profile.lower() :
            # XTEA uses Add/Sub/Shift/XOR
            # We MUST keep add_count and sub_count!
            core_counts['sbox_count'] = 0
            core_counts['perm_count'] = 0
            
            # XTEA doesn't strictly use Z-sequence, it uses a Delta constant
            # If regex found z_seq triggers by mistake, zero them out
            core_counts['z_seq_usage'] = 0
            
        return core_counts

    def _detect_z_sequence_usage(self) -> int:
        """Detect if Z-sequences are used in cryptographic context"""
        crypto_funcs = self._get_cryptographic_core_functions()
        
        for func_name, body in crypto_funcs.items():
            # Check if Z-sequences are used in key schedule or rounds
            if re.search(r'(get_z_bit_val|z0|z1|z2|z3|z4).*(key|round|schedule)', body, re.IGNORECASE):
                return 1
        return 0

    def _extract_rotation_amounts(self) -> List[int]:
        """Extract rotation amounts from Feistel operations"""
        rotation_amounts = []
        
        # Look specifically in F_function for Simon's rotations (1, 8, 2)
        crypto_funcs = self._get_cryptographic_core_functions()
        for func_name, body in crypto_funcs.items():
            # Simon F_function pattern: word_rotl 1 x, word_rotl 8 x, word_rotl 2 x
            rot_matches = re.findall(r'word_rotl\s+(\d+)', body)
            for amount in rot_matches:
                try:
                    rotation_amounts.append(int(amount))
                except ValueError:
                    continue
        
        # Simon typically uses specific rotation amounts (1, 8, 2)
        if not rotation_amounts:
            # Default Simon rotation amounts based on common implementations
            rotation_amounts = [1, 8, 2]
        
        return list(set(rotation_amounts))

    def _get_cryptographic_core_functions(self) -> Dict[str, str]:
        """Extract true cryptographic functions for Feistel ciphers"""
        crypto_functions = {}
        
        # EXCLUDE configuration/helper functions
        excluded_functions = {
            'get_num_rounds', 'get_z_array_index', 'get_z_bit_val',
            'z0', 'z1', 'z2', 'z3', 'z4', 'rho_const', 'block_size',
            'key_size', 'word_size', 'num_rounds'
        }
        
        # INCLUDE Feistel cryptographic core functions
        feistel_priority = [
            'F_function', 'simon_round', 'encrypt', 'decrypt',
            'gen_key_schedule_rec', 'generate_key_schedule',
            'encrypt_iterate', 'decrypt_iterate', 
            'encrypt_block', 'decrypt_block', 'decrypt_round_inv'
        ]
        
        # First, get all definitions
        definitions_dict = dict(self.definitions)
        
        # Priority 1: Explicit Feistel cryptographic functions
        for func_name in feistel_priority:
            if func_name in definitions_dict and func_name not in excluded_functions:
                crypto_functions[func_name] = definitions_dict[func_name]
        
        # Priority 2: Functions containing Feistel operations
        for func_name, body in self.definitions:
            if (func_name not in crypto_functions and 
                func_name not in excluded_functions and
                self._contains_feistel_operations(body)):
                crypto_functions[func_name] = body
        
        return crypto_functions

    def _contains_feistel_operations(self, body: str) -> bool:
        """Check if function body contains Feistel operations"""
        feistel_indicators = [
            r'word_rotl\s+\d+',  # rotations with amounts
            r'F_function',        # F-function calls
            r'simon_round',       # round function
            r'\bxor\s+',         # bitwise operations  
            r'\band\s+',
            r'key_schedule',     # key expansion
            r'encrypt', 'decrypt'
        ]
        
        for indicator in feistel_indicators:
            if re.search(indicator, body, re.IGNORECASE):
                return True
        return False

    def _analyze_feistel_structure(self) -> Dict[str, Any]:
        """Analyze Feistel network structure and properties"""
        structure_info = {
            "f_function_complexity": 0,
            "round_structure_detected": False,
            "left_right_halves": False,
            "key_schedule_type": "simple"
        }
        
        # Analyze F-function complexity
        f_func_body = None
        for func_name, body in self._get_cryptographic_core_functions().items():
            if 'F_function' in func_name:
                f_func_body = body
                break
        
        if f_func_body:
            # Count operations in F-function
            op_counts = CoreFunctionOperationCounter._count_operations_in_text(f_func_body, cipher_family = "Feistel")
            structure_info["f_function_complexity"] = sum(op_counts.values())
        
        # Check for left/right half structure
        if re.search(r'\b(left|right|L|R)\b', self.content, re.IGNORECASE):
            structure_info["left_right_halves"] = True
        
        # Analyze key schedule complexity
        key_schedule_complexity = 0
        for func_name, body in self._get_cryptographic_core_functions().items():
            if 'key_schedule' in func_name.lower():
                op_counts = CoreFunctionOperationCounter._count_operations_in_text(body, cipher_family = "Feistel")
                key_schedule_complexity = sum(op_counts.values())
                break
        
        if key_schedule_complexity > 10:
            structure_info["key_schedule_type"] = "complex"
        elif key_schedule_complexity > 5:
            structure_info["key_schedule_type"] = "moderate"
        else:
            structure_info["key_schedule_type"] = "simple"
        
        return structure_info

    def extract(self) -> Dict[str, Any]:
        fname = os.path.basename(self.thy_path)
        var = self._variants_from_filename(fname)
        if not var:
            raise ValueError("Filename doesn't contain block/key variant info")
        block_size, key_size = var
        
        # ===  Detect Variant Type from Filename ===
        variant_tag = None
        if "_Broken" in fname:
            variant_tag = "Broken"
        elif "_Low" in fname:
            variant_tag = "Low"
            
        # === 2. CORRECT ROUND DETERMINATION ===
        rounds = None
        
        # First: Try to find exact match in ATTACK_DB (e.g. Broken/Low specs)
        # This fixes the bug where "Broken" got the standard round count
        if variant_tag:
            attack_lookup = (block_size, key_size, variant_tag)
            if self.profile in ATTACK_DB and attack_lookup in ATTACK_DB[self.profile]:
                rounds = ATTACK_DB[self.profile][attack_lookup]['total_rounds']
                # print(f"DEBUG: Found {variant_tag} rounds for {fname}: {rounds}")

        # Second: If not found (or no tag), fall back to Standard Profile
        if rounds is None:
            cp = CIPHER_PROFILES.get(self.profile, {})
            if cp:
                for vname, vinfo in cp.get("variants", {}).items():
                    if vinfo.get("block_size") == block_size and vinfo.get("key_size") == key_size:
                        rounds = vinfo.get("rounds")
                        break
        
        # Fallback if still None
        if rounds is None:
            rounds = 32 # Default fallback

        # === ENHANCED: FILTER AND PARSE CRYPTOGRAPHIC FUNCTIONS ===
        core_functions = self._get_cryptographic_core_functions()
        
        # Parse only cryptographic core functions into enhanced AST
        for fname_def, body in core_functions.items():
            self.functions.append(fname_def)
            
            # 1. Clean the body of comments
            clean_body = self._clean_function_body(body)
        
            # 2. Find the *actual* expression.
            rhs = ""
            # Try to find '... = ...'
            equals_match = re.search(r'=\s*(.*)', clean_body, re.DOTALL)
            if equals_match:
                rhs = equals_match.group(1).strip()
            else:
                # If no '=', it might be a 'where' clause. Find the first quote.
                quote_match = re.search(r'"(.*?)"', clean_body, re.DOTALL)
                if quote_match:
                    rhs = quote_match.group(1).strip()
                else:
                    rhs = clean_body # Fallback
    
            # 3. Handle 'fun'/'definition' definitions that have the name in the body, e.g.,
            #    "present_round ... = p_layer_bitwise ..."
            if rhs.startswith(fname_def):
                # Split on the *first* equals sign and take the part after it
                if '=' in rhs:
                    rhs = rhs.split('=', 1)[1].strip()
                    
            # 4. === THIS IS THE KEY FIX ===
            #    Aggressively strip any *single* layer of surrounding quotes
            if rhs.startswith('"'):
                rhs = rhs[1:]
            if rhs.endswith('"'):
                rhs = rhs[:-1]
            rhs = rhs.strip()
            
            # 5. Final cleanup of internal whitespace
            rhs = re.sub(r'\s+', ' ', rhs) 
            
            # Add this line to confirm the fix
            # print(f"DEBUG: Parsing {fname_def} with CLEANED RHS: [{rhs}]")
            
            
            try:
                ast_tree = ExpressionParser.parse_expr_improved(rhs)
            except Exception as e:
                print(f"✗ Failed to parse {fname_def}: {e}")
                ast_tree = {"error": "parse_failed", "raw": rhs[:100]}
            
            # Use enhanced cryptographic AST extraction
            nodes_local, edges_local, _ = ast_to_nodes_edges_cryptographic(
                ast_tree, base_id=len(self.nodes), context=fname_def, 
                cipher_family=self._get_cipher_family()
            )
            
            # Detect cryptographic patterns in this function
            crypto_patterns = detect_cryptographic_patterns(nodes_local, edges_local, self._get_cipher_family())
            
            # Enhanced function node with pattern information
            func_node_id = len(self.nodes) + len(nodes_local)
            func_node = {
                "id": func_node_id, 
                "type": "function", 
                "label": fname_def,
                "cryptographic_patterns": crypto_patterns
            }
            
            self.nodes.append(func_node)
            self.nodes.extend(nodes_local)
            self.edges.extend(edges_local)
            
            if nodes_local:
                self.edges.append({"source": func_node_id, "target": nodes_local[0]["id"], "type": "contains"})

        # Use Simon-specific operation counting
        op_counts = self._count_feistel_operations(debug=False)
        
        # Enhanced Feistel feature detection
        rotation_amounts = self._extract_rotation_amounts()
        z_sequence_usage = self._detect_z_sequence_usage()
        feistel_structure = self._analyze_feistel_structure()
        
        # Enhanced Feistel detection with cryptographic context
        has_round_function = any('simon_round' in func for func in self.functions)
        has_f_function = any('F_function' in func for func in self.functions)
        has_enc_round = has_round_function
        has_dec_round = any('decrypt_round' in func for func in self.functions)
        has_key_schedule = any('key_schedule' in func.lower() for func in self.functions)

        # Calculate Feistel-specific metrics
        f_function_complexity = feistel_structure["f_function_complexity"] or (
            op_counts['xor_count'] + op_counts['and_count'] + op_counts['rotl_count']
        )
        feistel_balance = self._calculate_feistel_balance(op_counts)
        
        pdv = {
            "source_file": os.path.basename(self.thy_path),
            "cipher_family": "Feistel",
            "cipher_name": self.profile,
            "block_size": block_size,
            "key_size": key_size,
            "rounds": rounds,
            
            "feistel_structure": {
                "has_round_function": int(has_round_function),
                "has_f_function": int(has_f_function),
                "has_enc_round": int(has_enc_round),
                "has_dec_round": int(has_dec_round),
                "has_key_schedule": int(has_key_schedule),
                "rotation_diversity": len(set(rotation_amounts)),
                "max_rotation_amount": max(rotation_amounts, default=0),
                "rotation_amounts": rotation_amounts,
                "f_function_complexity": f_function_complexity,
                "uses_z_sequence": z_sequence_usage,
                "left_right_halves": feistel_structure["left_right_halves"],
                "key_schedule_complexity": feistel_structure["key_schedule_type"],
                "feistel_balance": feistel_balance,
            },
            
            "ops_summary": op_counts
        }

        self.pdv = pdv
        
        # Security scoring
        # === FIXING THE SCORER ===
        scorer = SecurityScorer(self.profile, block_size, key_size, rounds if rounds is not None else 0)
        
        # === CRITICAL FIX: PASS variant_tag ===
        #print('variant_tag', variant_tag)
        
        sec_score, sec_label = scorer.compute(variant_tag=variant_tag)
        # ======================================
        
        cipher_variant = f"{self.profile}_{block_size}_{key_size}"
        if variant_tag:
            cipher_variant += f"_{variant_tag}"
            
        all_label_computations[cipher_variant] = sec_label

        # Create unified PDV with cryptographic depth
        processor = UnifiedPDVProcessor()
        ast_data = {
            "nodes": self.nodes,
            "edges": self.edges, 
            "functions": self.functions
        }
        unified_pdv = processor.create_unified_pdv(pdv, ast_data)
       
        print(f"\n=== FEISTEL EXTRACTION SUMMARY: {cipher_variant} ===")
        print(f"Security: {sec_score} ({sec_label})")
        print(f"Rotation amounts: {rotation_amounts}")
        print(f"Z-sequence usage: {z_sequence_usage}")
        print(f"F-function complexity: {f_function_complexity}")
        print(f"Feistel balance: {feistel_balance:.3f}")
        print(f"Key schedule type: {feistel_structure['key_schedule_type']}")
        print(f"Cryptographic functions: {self.functions}")
        print(f"Total AST nodes: {len(self.nodes)}")
        print(f"Total AST edges: {len(self.edges)}")

        return {
            "cipher_variant": cipher_variant,
            "nodes": self.nodes,
            "edges": self.edges,
            "functions": self.functions,
            "pdv": pdv,
            "unified_pdv": unified_pdv,
            "security_score": sec_score,
            "security_label": sec_label
        }

    def _calculate_feistel_balance(self, op_counts: Dict[str, int]) -> float:
        """Calculate how balanced the Feistel operations are"""
        # Simon uses XOR, AND, ROTL in specific proportions
        xor_ops = op_counts.get('xor_count', 0)
        and_ops = op_counts.get('and_count', 0)
        rotl_ops = op_counts.get('rotl_count', 0)
        
        total_feistel_ops = xor_ops + and_ops + rotl_ops
        if total_feistel_ops == 0:
            return 0.0
        
        # Simon typically has more XORs than ANDs, with rotations for diffusion
        # Good balance means having all three operation types present
        operation_variety = len([op for op in [xor_ops, and_ops, rotl_ops] if op > 0]) / 3.0
        
        # Balance between linear (XOR) and nonlinear (AND) operations
        if xor_ops + and_ops > 0:
            linear_nonlinear_balance = min(xor_ops, and_ops) / max(xor_ops, and_ops)
        else:
            linear_nonlinear_balance = 0.0
        
        # Overall balance score
        balance_score = (operation_variety + linear_nonlinear_balance) / 2.0
        
        return max(0.0, balance_score)

    def _clean_function_body(self, body: str) -> str:
        """Clean function body for better parsing"""
        # Remove block comments
        body = re.sub(r'\(\*.*?\*\)', '', body, flags=re.DOTALL)
        # Remove line comments
        body = re.sub(r'--.*$', '', body, flags=re.MULTILINE)
        # Remove extra whitespace
        body = re.sub(r'\s+', ' ', body)
        return body.strip()


        
# =============================================================================
# ENHANCED ARX EXTRACTOR WITH CRYPTOGRAPHIC DEPTH
# =============================================================================

class ARXExtractor(CipherExtractor):
    def _count_arx_operations(self, debug: bool = False) -> Dict[str, int]:
        """FIXED: Speck-specific operation counting"""
        # Use the corrected operation counter
        core_counts = CoreFunctionOperationCounter.count_operations_in_core_functions(
            self.content, self._get_cipher_family(), debug
        )

        # Filter based on cipher
        if "speck" in self.profile.lower():
            core_counts['and_count'] = 0      
            core_counts['sbox_count'] = 0     
            core_counts['perm_count'] = 0     
            core_counts['z_seq_usage'] = 0    
            
        elif "lea" in self.profile.lower():
            # LEA is ARX, so keep Add/Rot/Xor.
            # Ensure Sbox/Perm are 0
            core_counts['sbox_count'] = 0
            core_counts['perm_count'] = 0
            # LEA does NOT use Speck's alpha/beta shift parameters
            core_counts['uses_shift_params'] = 0
        
        # # Speck-specific adjustments
        # core_counts['and_count'] = 0      # Speck doesn't use AND
        # core_counts['sbox_count'] = 0     # Speck has no S-boxes
        # core_counts['perm_count'] = 0     # Speck has no permutations
        # core_counts['z_seq_usage'] = 0    # Speck doesn't use Z-sequences
        
        return core_counts

    def _analyze_arx_structure(self) -> Dict[str, Any]:
        """FIXED: Analyze ARX structure and properties - CONSISTENT with Feistel"""
        structure_info = {
            "enc_round_complexity": 0,
            "rotation_diversity": 0,
            "arx_operation_balance": 0.0,
            "has_bidirectional_rotations": False,
            "key_schedule_type": "simple"
        }
        
        # Analyze encryption round complexity
        enc_round_body = None
        for func_name, body in self._get_cryptographic_core_functions().items():
            if 'speck_enc_round' in func_name:
                enc_round_body = body
                break
        
        if enc_round_body:
            # Count operations in encryption round
            op_counts = CoreFunctionOperationCounter._count_operations_in_text(enc_round_body, "ARX")
            structure_info["enc_round_complexity"] = sum(op_counts.values())
        
        # Check for bidirectional rotations
        rotation_amounts = self._extract_rotation_amounts()
        structure_info["rotation_diversity"] = len(set(rotation_amounts))
        
        # Check if both left and right rotations are used
        crypto_funcs = self._get_cryptographic_core_functions()
        has_rotl = any('word_rotl' in body for _, body in crypto_funcs.items())
        has_rotr = any('word_rotr' in body for _, body in crypto_funcs.items())
        structure_info["has_bidirectional_rotations"] = has_rotl and has_rotr
        
        # Analyze key schedule complexity
        key_schedule_complexity = 0
        for func_name, body in self._get_cryptographic_core_functions().items():
            if 'key_schedule' in func_name.lower():
                op_counts = CoreFunctionOperationCounter._count_operations_in_text(body, "ARX")
                key_schedule_complexity = sum(op_counts.values())
                break
        
        if key_schedule_complexity > 15:
            structure_info["key_schedule_type"] = "complex"
        elif key_schedule_complexity > 8:
            structure_info["key_schedule_type"] = "moderate"
        else:
            structure_info["key_schedule_type"] = "simple"
        
        return structure_info

    def _get_cryptographic_core_functions(self) -> Dict[str, str]:
        """FIXED: Extract true cryptographic functions for ARX ciphers - CONSISTENT"""
        crypto_functions = {}
        
        # EXCLUDE configuration/helper functions
        excluded_functions = {
            'get_num_rounds', 'get_shift_params', 'block_size',
            'key_size', 'word_size', 'num_rounds', 'alpha', 'beta'
        }
        
        # INCLUDE ARX cryptographic core functions - UPDATED to match theory files
        arx_priority = [
            'speck_enc_round', 'speck_dec_round', 'encrypt', 'decrypt',
            'gen_key_schedule_rec', 'generate_key_schedule',
            'encrypt_iterate', 'decrypt_iterate', 
            'encrypt_block', 'decrypt_block', 'decrypt_round_inv'
        ]
        
        # First, get all definitions
        definitions_dict = dict(self.definitions)
        
        # Priority 1: Explicit ARX cryptographic functions
        for func_name in arx_priority:
            if func_name in definitions_dict and func_name not in excluded_functions:
                crypto_functions[func_name] = definitions_dict[func_name]
        
        # Priority 2: Functions containing ARX operations
        for func_name, body in self.definitions:
            if (func_name not in crypto_functions and 
                func_name not in excluded_functions and
                self._contains_arx_operations(body)):
                crypto_functions[func_name] = body
        
        return crypto_functions

    def extract(self) -> Dict[str, Any]:
        fname = os.path.basename(self.thy_path)
        var = self._variants_from_filename(fname)
        if not var:
            raise ValueError("Filename doesn't contain variant info")
        block_size, key_size = var
        
        
        # ===  Detect Variant Type from Filename ===
        variant_tag = None
        if "_Broken" in fname:
            variant_tag = "Broken"
        elif "_Low" in fname:
            variant_tag = "Low"
            
        # === 2. CORRECT ROUND DETERMINATION ===
        rounds = None
        
        # First: Try to find exact match in ATTACK_DB (e.g. Broken/Low specs)
        # This fixes the bug where "Broken" got the standard round count
        if variant_tag:
            print('variant_tag ', variant_tag)
            attack_lookup = (block_size, key_size, variant_tag)
            if self.profile in ATTACK_DB and attack_lookup in ATTACK_DB[self.profile]:
                rounds = ATTACK_DB[self.profile][attack_lookup]['total_rounds']
                print(f"DEBUG: Found {variant_tag} rounds for {fname}: {rounds}")

        # Second: If not found (or no tag), fall back to Standard Profile
        if rounds is None:
            cp = CIPHER_PROFILES.get(self.profile, {})
            if cp:
                for vname, vinfo in cp.get("variants", {}).items():
                    if vinfo.get("block_size") == block_size and vinfo.get("key_size") == key_size:
                        rounds = vinfo.get("rounds")
                        break
        print(f"DEBUG: Found {variant_tag} rounds for {fname}: {rounds}")
        
        # Fallback if still None
        if rounds is None:
            rounds = 32 # Default fallback
            

        # === ENHANCED: FILTER AND PARSE CRYPTOGRAPHIC FUNCTIONS ===
        core_functions = self._get_cryptographic_core_functions()
        
        # Parse only cryptographic core functions into enhanced AST
        for fname_def, body in core_functions.items():
            self.functions.append(fname_def)
            
            clean_body = self._clean_function_body(body)
        
            # 2. Find the *actual* expression.
            rhs = ""
            # Try to find '... = ...'
            equals_match = re.search(r'=\s*(.*)', clean_body, re.DOTALL)
            if equals_match:
                rhs = equals_match.group(1).strip()
            else:
                # If no '=', it might be a 'where' clause. Find the first quote.
                quote_match = re.search(r'"(.*?)"', clean_body, re.DOTALL)
                if quote_match:
                    rhs = quote_match.group(1).strip()
                else:
                    rhs = clean_body # Fallback
    
            # 3. Handle 'fun'/'definition' definitions that have the name in the body, e.g.,
            #    "present_round ... = p_layer_bitwise ..."
            if rhs.startswith(fname_def):
                # Split on the *first* equals sign and take the part after it
                if '=' in rhs:
                    rhs = rhs.split('=', 1)[1].strip()
                    
            # 4. === THIS IS THE KEY FIX ===
            #    Aggressively strip any *single* layer of surrounding quotes
            if rhs.startswith('"'):
                rhs = rhs[1:]
            if rhs.endswith('"'):
                rhs = rhs[:-1]
            rhs = rhs.strip()
            # ============================
            
            # 5. Final cleanup of internal whitespace
            rhs = re.sub(r'\s+', ' ', rhs) 
            
            # Add this line to confirm the fix
            # print(f"DEBUG: Parsing {fname_def} with CLEANED RHS: [{rhs}]")
            
            try:
                ast_tree = ExpressionParser.parse_expr_improved(rhs)
            except Exception as e:
                print(f"✗ Failed to parse {fname_def}: {e}")
                ast_tree = {"error": "parse_failed", "raw": rhs[:100]}
            
            # Use enhanced cryptographic AST extraction
            nodes_local, edges_local, _ = ast_to_nodes_edges_cryptographic(
                ast_tree, base_id=len(self.nodes), context=fname_def, 
                cipher_family=self._get_cipher_family()
            )
            
            # Detect cryptographic patterns in this function
            crypto_patterns = detect_cryptographic_patterns(nodes_local, edges_local, self._get_cipher_family())
            
            # Enhanced function node with pattern information
            func_node_id = len(self.nodes) + len(nodes_local)
            func_node = {
                "id": func_node_id, 
                "type": "function", 
                "label": fname_def,
                "cryptographic_patterns": crypto_patterns
            }
            
            self.nodes.append(func_node)
            self.nodes.extend(nodes_local)
            self.edges.extend(edges_local)
            
            if nodes_local:
                self.edges.append({"source": func_node_id, "target": nodes_local[0]["id"], "type": "contains"})

        # Use Speck-specific operation counting
        op_counts = self._count_arx_operations(debug=False)
        
        # Enhanced ARX feature detection
        rotation_amounts = self._extract_rotation_amounts()
        shift_params_usage = self._detect_shift_params_usage()
        arx_structure = self._analyze_arx_structure()  # NEW: Consistent structure analysis
        
        # Enhanced ARX detection with cryptographic context
        has_enc_round = any('speck_enc_round' in func for func in self.functions)
        has_dec_round = any('speck_dec_round' in func for func in self.functions)
        has_key_schedule = any('key_schedule' in func.lower() for func in self.functions)
        has_round_function = has_enc_round or has_dec_round

        # Calculate ARX-specific metrics
        arx_operation_balance = self._calculate_arx_balance(op_counts)
        round_complexity = arx_structure["enc_round_complexity"] or (
            op_counts['add_count'] + op_counts['xor_count'] + op_counts['rotl_count'] + op_counts['rotr_count']
        )
        
        pdv = {
            "source_file": os.path.basename(self.thy_path),
            "cipher_family": "ARX",
            "cipher_name": self.profile,
            "block_size": block_size,
            "key_size": key_size,
            "rounds": rounds,
            
            "arx_structure": {
                "has_enc_round": int(has_enc_round),
                "has_dec_round": int(has_dec_round),
                "has_key_schedule": int(has_key_schedule),
                "has_round_function": int(has_round_function),
                "enc_round_complexity": round_complexity,
                "rotation_diversity": arx_structure["rotation_diversity"],
                "max_rotation_amount": max(rotation_amounts, default=0),
                "rotation_amounts": rotation_amounts,
                "arx_operation_balance": arx_operation_balance,
                "has_bidirectional_rotations": int(arx_structure["has_bidirectional_rotations"]),
                "key_schedule_complexity": arx_structure["key_schedule_type"],
            },
            
            "shift_parameters": {
                "shift_params_defined": bool(shift_params_usage),
                "uses_shift_params": shift_params_usage
            },
            
            "ops_summary": op_counts
        }
        
        self.pdv = pdv
        
        # Security scoring
        scorer = SecurityScorer(self.profile, block_size, key_size, rounds if rounds is not None else 0)
        
        # === CRITICAL FIX: PASS variant_tag ===
        #print('variant_tag', variant_tag)
        
        sec_score, sec_label = scorer.compute(variant_tag=variant_tag)
        # ======================================
        
        cipher_variant = f"{self.profile}_{block_size}_{key_size}"
        if variant_tag:
            cipher_variant += f"_{variant_tag}"
            
        all_label_computations[cipher_variant] = sec_label
        
        # Create unified PDV with cryptographic depth
        processor = UnifiedPDVProcessor()
        ast_data = {
            "nodes": self.nodes,
            "edges": self.edges, 
            "functions": self.functions
        }
        unified_pdv = processor.create_unified_pdv(pdv, ast_data)
       
        print(f"\n=== ARX EXTRACTION SUMMARY: {cipher_variant} ===")
        print(f"Security: {sec_score} ({sec_label})")
        print(f"Rotation amounts: {rotation_amounts}")
        print(f"Shift parameters usage: {shift_params_usage}")
        print(f"ARX operation balance: {arx_operation_balance:.3f}")
        print(f"Bidirectional rotations: {arx_structure['has_bidirectional_rotations']}")
        print(f"Key schedule type: {arx_structure['key_schedule_type']}")
        print(f"Cryptographic functions: {self.functions}")
        print(f"Total AST nodes: {len(self.nodes)}")
        print(f"Total AST edges: {len(self.edges)}")

        return {
            "cipher_variant": cipher_variant,
            "nodes": self.nodes,
            "edges": self.edges,
            "functions": self.functions,
            "pdv": pdv,
            "unified_pdv": unified_pdv,
            "security_score": sec_score,
            "security_label": sec_label
        }
       
    def _calculate_arx_balance(self, op_counts: Dict[str, int]) -> float:
        """Calculate how balanced the ARX operations are"""
        add_ops = op_counts.get('add_count', 0)
        rot_ops = op_counts.get('rotl_count', 0) + op_counts.get('rotr_count', 0)
        xor_ops = op_counts.get('xor_count', 0)
        
        total_arx_ops = add_ops + rot_ops + xor_ops
        if total_arx_ops == 0:
            return 0.0
        
        # Ideal balance would have similar counts of each operation type
        ideal_per_op = total_arx_ops / 3.0
        balance_score = 1.0 - (
            abs(add_ops - ideal_per_op) + 
            abs(rot_ops - ideal_per_op) + 
            abs(xor_ops - ideal_per_op)
        ) / (2.0 * total_arx_ops)
        
        return max(0.0, balance_score)

    def _clean_function_body(self, body: str) -> str:
        """Clean function body for better parsing"""
        # Remove block comments
        body = re.sub(r'\(\*.*?\*\)', '', body, flags=re.DOTALL)
        # Remove line comments
        body = re.sub(r'--.*$', '', body, flags=re.MULTILINE)
        # Remove extra whitespace
        body = re.sub(r'\s+', ' ', body)
        return body.strip()

    def _contains_arx_operations(self, body: str) -> bool:
        """Check if function body contains ARX operations"""
        arx_indicators = [
            r'word_rotl\s+\d+',    # rotations with amounts
            r'word_rotr\s+\d+',
            r'\badd\s+',           # modular addition
            r'\bxor\s+',           # bitwise XOR
            r'speck_enc_round',    # round function calls
            r'speck_dec_round',
            r'key_schedule',       # key expansion
        ]
        
        for indicator in arx_indicators:
            if re.search(indicator, body, re.IGNORECASE):
                return True
        return False

    def _detect_shift_params_usage(self) -> int:
        """Detect if shift parameters are used (Speck characteristic)"""
        shift_indicators = [
            r'get_shift_params', r'alpha_shift', r'beta_shift',
            r'alpha', r'beta'
        ]
        
        for indicator in shift_indicators:
            if re.search(indicator, self.content, re.IGNORECASE):
                return 1
        return 0

    def _extract_rotation_amounts(self) -> List[int]:
        """Extract rotation amounts from ARX operations"""
        rotation_amounts = []
        
        # Look for rotation operations in core functions
        crypto_funcs = self._get_cryptographic_core_functions()
        for func_name, body in crypto_funcs.items():
            # Find word_rotl and word_rotr with numeric amounts
            rotl_matches = re.findall(r'word_rotl\s+(\d+)', body)
            rotr_matches = re.findall(r'word_rotr\s+(\d+)', body)
            
            for amount in rotl_matches + rotr_matches:
                try:
                    rotation_amounts.append(int(amount))
                except ValueError:
                    continue
        
        # Speck typically uses specific rotation amounts (7, 2 for 32-bit)
        if not rotation_amounts:
            # Default Speck rotation amounts based on common implementations
            rotation_amounts = [7, 2] if "32" in os.path.basename(self.thy_path) else [8, 3]
        
        return list(set(rotation_amounts))



# =============================================================================
# EXTRACTOR FOR HIGHT (GFN with ARX ops)
# =============================================================================

class HIGHTExtractor(CipherExtractor):
    
    def _count_hight_operations(self, debug: bool = False) -> Dict[str, int]:
        """FIXED: HIGHT-specific operation counting"""
        # Use the corrected operation counter, now that it knows about "HIGHT_ARX"
        core_counts = CoreFunctionOperationCounter.count_operations_in_core_functions(
            self.content, self._get_cipher_family(), debug
        )
        
        return core_counts

    def _get_cryptographic_core_functions(self) -> Dict[str, str]:
        """Extract true cryptographic functions for HIGHT"""

        hight_priority = [
            'hight_enc_round', 
            #'hight_dec_round_inv',
            'hight_encrypt_iterate', 
            #'hight_decrypt_iterate',
            'hight_initial_trans', 
            'hight_final_trans',
            'hight_F0', 
            'hight_F1',
            #'hight_whitening_keys', 
            #'hight_gen_subkeys'
        ]
        
        definitions_dict = dict(self.definitions)
        crypto_functions = {}
        
        for func_name in hight_priority:
            if func_name in definitions_dict:
                crypto_functions[func_name] = definitions_dict[func_name]
                
        return crypto_functions
        

    def _analyze_hight_structure(self) -> Dict[str, Any]:
        """Analyze HIGHT network structure and properties"""
        structure_info = {
            "round_complexity": 0,
            "has_f_function_0": False,
            "has_f_function_1": False,
            "key_schedule_type": "simple"
        }
        
        f0_body = None
        f1_body = None
        round_body = None
        
        # return structure_info
        core_funcs = self._get_cryptographic_core_functions()

        for func_name, body in core_funcs.items():
            if 'enc_round' in func_name: # Matches hight_64_128_enc_round
                op_counts = CoreFunctionOperationCounter._count_operations_in_text(body, "HIGHT_ARX")
                structure_info["round_complexity"] = sum(op_counts.values())
            elif 'F0' in func_name:
                structure_info["has_f_function_0"] = True
            elif 'F1' in func_name:
                structure_info["has_f_function_1"] = True
            elif 'subkeys' in func_name: # Matches hight_64_128_gen_subkeys
                op_counts = CoreFunctionOperationCounter._count_operations_in_text(body, "HIGHT_ARX")
                if sum(op_counts.values()) > 10:
                     structure_info["key_schedule_type"] = "complex"
        
        return structure_info


    def _detect_delta_sequence_usage(self) -> int:
        """Detect if delta sequences are used (HIGHT characteristic)"""
        if re.search(r'\b(delta0|get_delta_bit_val|constant_generation)\b', self.content, re.IGNORECASE):
            return 1
        return 0

    def _extract_rotation_amounts(self) -> List[int]:
        """Extract rotation amounts from HIGHT operations"""
        rotation_amounts = []
        crypto_funcs = self._get_cryptographic_core_functions()
        for func_name, body in crypto_funcs.items():
            # Find rotate_bits_left or word_rotl
            rot_matches = re.findall(r'(?:word_rotl|rotate_bits_left)\s+(\d+)', body)
            for amount in rot_matches:
                try:
                    rotation_amounts.append(int(amount))
                except ValueError:
                    continue
        
        # From HIGHT.thy, F_function_0 uses (1, 2, 7) and F_function_1 uses (3, 4, 6)
        if not rotation_amounts:
            rotation_amounts = [1, 2, 7, 3, 4, 6]
            
        return list(set(rotation_amounts))

    def _calculate_arx_balance(self, op_counts: Dict[str, int]) -> float:
        """Calculate how balanced the ARX operations are"""
        add_ops = op_counts.get('add_count', 0) + op_counts.get('sub_count', 0)
        rot_ops = op_counts.get('rotl_count', 0) + op_counts.get('rotr_count', 0)
        xor_ops = op_counts.get('xor_count', 0)
        
        total_arx_ops = add_ops + rot_ops + xor_ops
        if total_arx_ops == 0:
            return 0.0
        
        # Ideal balance would have similar counts of each operation type
        ideal_per_op = total_arx_ops / 3.0
        balance_score = 1.0 - (
            abs(add_ops - ideal_per_op) +  
            abs(rot_ops - ideal_per_op) +  
            abs(xor_ops - ideal_per_op)
        ) / (2.0 * total_arx_ops)
        
        return max(0.0, balance_score)

    def extract(self) -> Dict[str, Any]:
        fname = os.path.basename(self.thy_path)
        var = self._variants_from_filename(fname)
        if not var:
            raise ValueError("Filename doesn't contain variant info")
        block_size, key_size = var

        # ===  Detect Variant Type from Filename ===
        variant_tag = None
        if "_Broken" in fname:
            variant_tag = "Broken"
        elif "_Low" in fname:
            variant_tag = "Low"

        
        # === 2. CORRECT ROUND DETERMINATION ===
        rounds = None
        
        # First: Try to find exact match in ATTACK_DB (e.g. Broken/Low specs)
        # This fixes the bug where "Broken" got the standard round count
        if variant_tag:
            attack_lookup = (block_size, key_size, variant_tag)
            if self.profile in ATTACK_DB and attack_lookup in ATTACK_DB[self.profile]:
                rounds = ATTACK_DB[self.profile][attack_lookup]['total_rounds']
                # print(f"DEBUG: Found {variant_tag} rounds for {fname}: {rounds}")

        # Second: If not found (or no tag), fall back to Standard Profile
        if rounds is None:
            cp = CIPHER_PROFILES.get(self.profile, {})
            if cp:
                for vname, vinfo in cp.get("variants", {}).items():
                    if vinfo.get("block_size") == block_size and vinfo.get("key_size") == key_size:
                        rounds = vinfo.get("rounds")
                        break
        
        # Fallback if still None
        if rounds is None:
            rounds = 32 # Default fallback
        
        # === FILTER AND PARSE CRYPTOGRAPHIC FUNCTIONS ===
        core_functions = self._get_cryptographic_core_functions()
        
        for fname_def, body in core_functions.items():
            self.functions.append(fname_def)
            
            # 1. Clean the body of comments
            clean_body = self._clean_function_body(body)
    
            # 2. Find the *actual* expression.
            rhs = ""
            # Try to find '... = ...'
            equals_match = re.search(r'=\s*(.*)', clean_body, re.DOTALL)
            if equals_match:
                rhs = equals_match.group(1).strip()
            else:
                # If no '=', it might be a 'where' clause. Find the first quote.
                quote_match = re.search(r'"(.*?)"', clean_body, re.DOTALL)
                if quote_match:
                    rhs = quote_match.group(1).strip()
                else:
                    rhs = clean_body # Fallback
    
            # 3. Handle 'fun'/'definition' definitions that have the name in the body
            if rhs.startswith(fname_def):
                if '=' in rhs:
                    rhs = rhs.split('=', 1)[1].strip()
                    
            # 4. Aggressively strip any *single* layer of surrounding quotes
            if rhs.startswith('"'):
                rhs = rhs[1:]
            if rhs.endswith('"'):
                rhs = rhs[:-1]
            rhs = rhs.strip()
            
            # 5. Final cleanup of internal whitespace
            rhs = re.sub(r'\s+', ' ', rhs) 
            
            # print(f"DEBUG: Parsing {fname_def} with CLEANED RHS: [{rhs}]")
            
            try:
                ast_tree = ExpressionParser.parse_expr_improved(rhs)
            except Exception as e:
                print(f"✗ Failed to parse {fname_def}: {e}")
                ast_tree = {"error": "parse_failed", "raw": rhs[:100]}
            
            nodes_local, edges_local, _ = ast_to_nodes_edges_cryptographic(
                ast_tree, base_id=len(self.nodes), context=fname_def, 
                cipher_family=self._get_cipher_family()
            )
            
            crypto_patterns = detect_cryptographic_patterns(nodes_local, edges_local, self._get_cipher_family())
            
            func_node_id = len(self.nodes) + len(nodes_local)
            func_node = {
                "id": func_node_id, 
                "type": "function", 
                "label": fname_def,
                "cryptographic_patterns": crypto_patterns
            }
            
            self.nodes.append(func_node)
            self.nodes.extend(nodes_local)
            self.edges.extend(edges_local)
            
            if nodes_local:
                self.edges.append({"source": func_node_id, "target": nodes_local[0]["id"], "type": "contains"})

        # Use HIGHT-specific operation counting
        op_counts = self._count_hight_operations(debug=False)
        
        # Enhanced HIGHT feature detection
        rotation_amounts = self._extract_rotation_amounts()
        delta_sequence_usage = self._detect_delta_sequence_usage()
        hight_structure = self._analyze_hight_structure()
        
        has_round_function = any('hight_encryption_round' in func for func in self.functions)
        has_key_schedule = any('key_schedule' in func.lower() for func in self.functions)
        arx_operation_balance = self._calculate_arx_balance(op_counts)

        pdv = {
            "source_file": os.path.basename(self.thy_path),
            "cipher_family": "HIGHT_ARX",  # Use our new family name
            "cipher_name": self.profile,   # This will be "HIGHT"
            "block_size": block_size,
            "key_size": key_size,
            "rounds": rounds,
            
            "hight_structure": {
                "has_round_function": int(has_round_function),
                "has_f_function_0": int(hight_structure["has_f_function_0"]),
                "has_f_function_1": int(hight_structure["has_f_function_1"]),
                "has_key_schedule": int(has_key_schedule),
                "round_complexity": hight_structure["round_complexity"],
                "rotation_diversity": len(set(rotation_amounts)),
                "max_rotation_amount": max(rotation_amounts, default=0),
                "rotation_amounts": rotation_amounts,
                "arx_operation_balance": arx_operation_balance,
                "uses_delta_sequence": delta_sequence_usage,
                "key_schedule_complexity": hight_structure["key_schedule_type"],
            },
            
            "ops_summary": op_counts
        }
        
        self.pdv = pdv
            
        # Security scoring
        scorer = SecurityScorer(self.profile, block_size, key_size, rounds if rounds is not None else 0)
        
        # === CRITICAL FIX: PASS variant_tag ===
        #print('variant_tag', variant_tag)
        
        sec_score, sec_label = scorer.compute(variant_tag=variant_tag)
        # ======================================
        
        cipher_variant = f"{self.profile}_{block_size}_{key_size}"
        if variant_tag:
            cipher_variant += f"_{variant_tag}"
            
        all_label_computations[cipher_variant] = sec_label

        
        # scorer = SecurityScorer(self.profile, block_size, key_size, rounds if rounds is not None else 0)
        # sec_score, sec_label = scorer.compute()
        # cipher_variant = f"{self.profile}_{block_size}_{key_size}"
        # all_label_computations[cipher_variant] = sec_label
        
        # Create unified PDV with cryptographic depth
        processor = UnifiedPDVProcessor()
        ast_data = {
            "nodes": self.nodes,
            "edges": self.edges, 
            "functions": self.functions
        }
        unified_pdv = processor.create_unified_pdv(pdv, ast_data)
        
        print(f"\n=== HIGHT EXTRACTION SUMMARY: {cipher_variant} ===")
        print(f"Security: {sec_score} ({sec_label})")
        print(f"Rotation amounts: {rotation_amounts}")
        print(f"Delta-sequence usage: {delta_sequence_usage}")
        print(f"ARX operation balance: {arx_operation_balance:.3f}")
        print(f"Key schedule type: {hight_structure['key_schedule_type']}")
        print(f"Cryptographic functions: {self.functions}")
        print(f"Total AST nodes: {len(self.nodes)}")
        print(f"Total AST edges: {len(self.edges)}")

        return {
            "cipher_variant": cipher_variant,
            "nodes": self.nodes,
            "edges": self.edges,
            "functions": self.functions,
            "pdv": pdv,
            "unified_pdv": unified_pdv,
            "security_score": sec_score,
            "security_label": sec_label
        }
    
    def _clean_function_body(self, body: str) -> str:
        """Clean function body for better parsing"""
        # Remove block comments
        body = re.sub(r'\(\*.*?\*\)', '', body, flags=re.DOTALL)
        # Remove line comments
        body = re.sub(r'--.*$', '', body, flags=re.MULTILINE)
        # Remove extra whitespace
        body = re.sub(r'\s+', ' ', body)
        return body.strip()

   

# =============================================================================
# ENHANCED SPN EXTRACTOR WITH CRYPTOGRAPHIC DEPTH
# =============================================================================


class SPNExtractor(CipherExtractor):
    def _count_spn_operations(self, debug: bool = False) -> Dict[str, int]:
        core_counts = CoreFunctionOperationCounter.count_operations_in_core_functions(
            self.content, self._get_cipher_family(), debug
        )
        
        cipher_name = self.profile.lower()
        
        if "sparx" in cipher_name:
            # SPARX is special: It is an SPN that uses ARX for S-boxes.
            # We KEEP add/rot counts.
            pass 
        else:
            # Standard SPN (PRESENT, GIFT, RECTANGLE) usually don't use modular addition
            # Zero them out to prevent noise
            core_counts['add_count'] = 0
            core_counts['sub_count'] = 0
            core_counts['rotl_count'] = 0
            core_counts['rotr_count'] = 0
            
        return core_counts


    def _analyze_spn_structure(self) -> Dict[str, Any]:
        """FIXED: Analyze SPN structure and properties - CONSISTENT with others"""
        structure_info = {
            "round_complexity": 0,
            "has_sbox_layer": False,
            "has_perm_layer": False,
            "layer_separation": False,
            "key_schedule_type": "simple",
            "confusion_diffusion_balance": 0.0
        }
        
        # Analyze round complexity
        round_body = None
        for func_name, body in self._get_cryptographic_core_functions().items():
            if 'present_round' in func_name:
                round_body = body
                break
        
        if round_body:
            # Count operations in round function
            op_counts = CoreFunctionOperationCounter._count_operations_in_text(round_body, "SPN")
            structure_info["round_complexity"] = sum(op_counts.values())
        
        # Check for layer separation
        crypto_funcs = self._get_cryptographic_core_functions()
        has_sbox = any('sbox' in func_name.lower() for func_name in crypto_funcs.keys())
        has_perm = any('p_layer' in func_name.lower() for func_name in crypto_funcs.keys())
        structure_info["has_sbox_layer"] = has_sbox
        structure_info["has_perm_layer"] = has_perm
        structure_info["layer_separation"] = has_sbox and has_perm
        
        # Analyze key schedule complexity
        key_schedule_complexity = 0
        for func_name, body in self._get_cryptographic_core_functions().items():
            if 'key_schedule' in func_name.lower() or 'key_update' in func_name.lower():
                op_counts = CoreFunctionOperationCounter._count_operations_in_text(body, "SPN")
                key_schedule_complexity = sum(op_counts.values())
                break
        
        if key_schedule_complexity > 20:
            structure_info["key_schedule_type"] = "complex"
        elif key_schedule_complexity > 10:
            structure_info["key_schedule_type"] = "moderate"
        else:
            structure_info["key_schedule_type"] = "simple"
        
        return structure_info

    def _get_cryptographic_core_functions(self) -> Dict[str, str]:
        """FIXED: Extract true cryptographic functions for SPN ciphers - CONSISTENT"""
        crypto_functions = {}
        
        # EXCLUDE configuration/helper functions
        # excluded_functions = {
        #     'get_num_rounds', 'block_size', 'key_size',
        #     'word_size', 'num_rounds', 'sbox_table', 'sbox_inv_table',
        #     'p_layer_map', 'p_layer_inv_map'
        # }
        # EXCLUDE configuration/helper functions
        excluded_functions = {
            'get_num_rounds', 'block_size', 'key_size',
            'word_size', 'num_rounds', 'sbox_table', 'sbox_inv_table',
            'p_layer_map', 'p_layer_inv_map', 'rectangle_rounds', 
            'rectangle_block_size', 'rectangle_key_size', 'rectangle_rc',
            # Skinny constants to exclude
            'skinny_rounds', 'skinny_sbox_table', 'skinny_sbox_inv_table', 
            'skinny_rc_table', 'skinny_sr_map', 'skinny_sr_inv_map',
        }
        
        # INCLUDE SPN cryptographic core functions - UPDATED to match theory files
        # INCLUDE SPN cryptographic core functions - UPDATED for RECTANGLE/GIFT/SPARX
        spn_priority = [
            # PRESENT
            'present_round', 'present_round_inv', 'sbox_layer', 'sbox_layer_inv',
            'p_layer_bitwise', 'p_layer_inv_bitwise', 'present_encrypt', 'present_decrypt',
            'present_encrypt_iterate', 'present_decrypt_iterate', 'encrypt', 'decrypt',
            'key_schedule', 'key_update', 'build_key_list', 'extract_round_key',
            
            # RECTANGLE 
            'rectangle_encrypt_round', 'rectangle_decrypt_round',
            'rectangle_encrypt_block', 'rectangle_decrypt_block',
            'rectangle_sub_column', 'rectangle_shift_rows',
            'rectangle_add_round_key', 'rectangle_generate_all_round_keys',
            'rectangle_encrypt', 'rectangle_decrypt',
            'rectangle_key_update_80',
            
            # GIFT 
            'gift_encrypt_round', 'gift_decrypt_round',
            'gift_encrypt_block', 'gift_decrypt_block',
            'gift_sbox_layer', 'gift_perm_layer',
            'gift_encrypt', 'gift_decrypt',
            
            # SPARX 
            'sparx_encrypt_block', 'sparx_decrypt_block',
            'sparx_encrypt', 'sparx_decrypt',
            'sparx_linear_layer', 'sparx_A_perm_16',

            # SKINNY
            'skinny_encrypt_round', # 'skinny_decrypt_round_inv',
            'skinny_encrypt_iterate',# 'skinny_decrypt_iterate',
            'skinny_sub_cells', #'skinny_sub_cells_inv',
            'skinny_add_round_constant', 
            'skinny_shift_rows', #'skinny_shift_rows_inv',
            'skinny_mix_columns', #'skinny_mix_columns_inv',
            'skinny_gen_keys', 'skinny_tk_update'
        ]
        
        # First, get all definitions
        definitions_dict = dict(self.definitions)
        
        # Priority 1: Explicit SPN cryptographic functions
        for func_name in spn_priority:
            if func_name in definitions_dict and func_name not in excluded_functions:
                crypto_functions[func_name] = definitions_dict[func_name]
        
        # Priority 2: Functions containing SPN operations
        for func_name, body in self.definitions:
            if (func_name not in crypto_functions and 
                func_name not in excluded_functions and
                self._contains_spn_operations(body)):
                crypto_functions[func_name] = body
        
        return crypto_functions

    def extract(self) -> Dict[str, Any]:
        fname = os.path.basename(self.thy_path)
        var = self._variants_from_filename(fname)
        if not var:
            raise ValueError("Filename doesn't contain variant info")
        block_size, key_size = var
        
        
        # ===  Detect Variant Type from Filename ===
        #print('fname', fname)
        variant_tag = None
        if "_Broken" in fname:
            variant_tag = "Broken"
        elif "_Low" in fname:
            variant_tag = "Low"
            
        # === 2. CORRECT ROUND DETERMINATION ===
        rounds = None
        
        # First: Try to find exact match in ATTACK_DB (e.g. Broken/Low specs)
        # This fixes the bug where "Broken" got the standard round count
        if variant_tag:
            attack_lookup = (block_size, key_size, variant_tag)
            if self.profile in ATTACK_DB and attack_lookup in ATTACK_DB[self.profile]:
                rounds = ATTACK_DB[self.profile][attack_lookup]['total_rounds']
                # print(f"DEBUG: Found {variant_tag} rounds for {fname}: {rounds}")

        # Second: If not found (or no tag), fall back to Standard Profile
        if rounds is None:
            cp = CIPHER_PROFILES.get(self.profile, {})
            if cp:
                for vname, vinfo in cp.get("variants", {}).items():
                    if vinfo.get("block_size") == block_size and vinfo.get("key_size") == key_size:
                        rounds = vinfo.get("rounds")
                        break
        
        # Fallback if still None
        if rounds is None:
            rounds = 32 # Default fallback
            

        # === ENHANCED: FILTER AND PARSE CRYPTOGRAPHIC FUNCTIONS ===
        core_functions = self._get_cryptographic_core_functions()
        
        # Parse only cryptographic core functions into enhanced AST
        for fname_def, body in core_functions.items():
            self.functions.append(fname_def)
            
            clean_body = self._clean_function_body(body)
        
            # 2. Find the *actual* expression.
            rhs = ""
            # Try to find '... = ...'
            equals_match = re.search(r'=\s*(.*)', clean_body, re.DOTALL)
            if equals_match:
                rhs = equals_match.group(1).strip()
            else:
                # If no '=', it might be a 'where' clause. Find the first quote.
                quote_match = re.search(r'"(.*?)"', clean_body, re.DOTALL)
                if quote_match:
                    rhs = quote_match.group(1).strip()
                else:
                    rhs = clean_body # Fallback
    
            # 3. Handle 'fun'/'definition' definitions that have the name in the body, e.g.,
            #    "present_round ... = p_layer_bitwise ..."
            if rhs.startswith(fname_def):
                # Split on the *first* equals sign and take the part after it
                if '=' in rhs:
                    rhs = rhs.split('=', 1)[1].strip()
                    
            # 4. === THIS IS THE KEY FIX ===
            #    Aggressively strip any *single* layer of surrounding quotes
            if rhs.startswith('"'):
                rhs = rhs[1:]
            if rhs.endswith('"'):
                rhs = rhs[:-1]
            rhs = rhs.strip()
            # ============================
            
            # 5. Final cleanup of internal whitespace
            rhs = re.sub(r'\s+', ' ', rhs) 
            
            # Add this line to confirm the fix
            # print(f"DEBUG: Parsing {fname_def} with CLEANED RHS: [{rhs}]")


            try:
                ast_tree = ExpressionParser.parse_expr_improved(rhs)
            except Exception as e:
                print(f"✗ Failed to parse {fname_def}: {e}")
                ast_tree = {"error": "parse_failed", "raw": rhs[:100]}
            
            # Use enhanced cryptographic AST extraction
            nodes_local, edges_local, _ = ast_to_nodes_edges_cryptographic(
                ast_tree, base_id=len(self.nodes), context=fname_def, 
                cipher_family=self._get_cipher_family()
            )
            
            # Detect cryptographic patterns in this function
            crypto_patterns = detect_cryptographic_patterns(nodes_local, edges_local, self._get_cipher_family())
            
            # Enhanced function node with pattern information
            func_node_id = len(self.nodes) + len(nodes_local)
            func_node = {
                "id": func_node_id, 
                "type": "function", 
                "label": fname_def,
                "cryptographic_patterns": crypto_patterns
            }
            
            self.nodes.append(func_node)
            self.nodes.extend(nodes_local)
            self.edges.extend(edges_local)
            
            if nodes_local:
                self.edges.append({"source": func_node_id, "target": nodes_local[0]["id"], "type": "contains"})

        # Use PRESENT-specific operation counting
        op_counts = self._count_spn_operations(debug=False)
        
        # Enhanced SPN feature detection
        sbox_info = self._analyze_sbox_structure()
        perm_info = self._analyze_permutation_structure()
        spn_structure = self._analyze_spn_structure()  # NEW: Consistent structure analysis
        
        # Enhanced SPN detection with cryptographic context
        has_sbox_layer = any('sbox' in func.lower() for func in self.functions)
        has_perm_layer = any('p_layer' in func.lower() for func in self.functions)
        has_round_function = any('present_round' in func for func in self.functions)
        has_key_schedule = any('key_schedule' in func.lower() for func in self.functions)

        # Calculate SPN-specific metrics
        round_complexity = spn_structure["round_complexity"] or (
            op_counts['sbox_count'] + op_counts['perm_count'] + op_counts['xor_count']
        )
        confusion_diffusion_balance = op_counts['sbox_count'] / max(op_counts['perm_count'] + op_counts['xor_count'], 1)
        
        pdv = {
            "source_file": os.path.basename(self.thy_path),
            "cipher_family": "SPN",
            "cipher_name": self.profile,
            "block_size": block_size,
            "key_size": key_size,
            "rounds": rounds,
            
            "spn_structure": {
                "has_sbox_layer": int(has_sbox_layer),
                "has_perm_layer": int(has_perm_layer),
                "has_round_function": int(has_round_function),
                "has_key_schedule": int(has_key_schedule),
                "round_complexity": round_complexity,
                "sbox_size": sbox_info["sbox_size"],
                "sbox_nonlinearity": sbox_info["sbox_nonlinearity"],
                "sbox_applications": op_counts['sbox_count'],
                "perm_applications": op_counts['perm_count'],
                "xor_applications": op_counts['xor_count'],
                "confusion_diffusion_balance": confusion_diffusion_balance,
                "layer_separation": int(spn_structure["layer_separation"]),
                "key_schedule_complexity": spn_structure["key_schedule_type"],
            },
            
            "sbox_info": sbox_info,
            "permutation_info": perm_info,
            
            "ops_summary": op_counts
        }
        
        self.pdv = pdv

        
        # Security scoring
        scorer = SecurityScorer(self.profile, block_size, key_size, rounds if rounds is not None else 0)
        
        # === CRITICAL FIX: PASS variant_tag ===
        #print('variant_tag', variant_tag)
        sec_score, sec_label = scorer.compute(variant_tag=variant_tag)
        # ======================================
        
        cipher_variant = f"{self.profile}_{block_size}_{key_size}"
        if variant_tag:
            cipher_variant += f"_{variant_tag}"
            
        all_label_computations[cipher_variant] = sec_label
        
        # # Security scoring
        # scorer = SecurityScorer("PRESENT", block_size, key_size, rounds if rounds is not None else 0)
        # sec_score, sec_label = scorer.compute()
        # cipher_variant = f"PRESENT_{block_size}_{key_size}"
        # all_label_computations[cipher_variant] = sec_label
        
        # Create unified PDV with cryptographic depth
        processor = UnifiedPDVProcessor()
        ast_data = {
            "nodes": self.nodes,
            "edges": self.edges, 
            "functions": self.functions
        }
        unified_pdv = processor.create_unified_pdv(pdv, ast_data)
       
        print(f"\n=== SPN EXTRACTION SUMMARY: {cipher_variant} ===")
        print(f"Security: {sec_score} ({sec_label})")
        print(f"S-box size: {sbox_info['sbox_size']} (defined: {sbox_info['sbox_defined']})")
        print(f"Permutation: {perm_info['perm_type']} (size: {perm_info['perm_size']})")
        print(f"Confusion-diffusion balance: {confusion_diffusion_balance:.3f}")
        print(f"Layer separation: {spn_structure['layer_separation']}")
        print(f"Key schedule type: {spn_structure['key_schedule_type']}")
        print(f"Cryptographic functions: {self.functions}")
        print(f"Total AST nodes: {len(self.nodes)}")
        print(f"Total AST edges: {len(self.edges)}")

        return {
            "cipher_variant": cipher_variant,
            "nodes": self.nodes,
            "edges": self.edges,
            "functions": self.functions,
            "pdv": pdv,
            "unified_pdv": unified_pdv,
            "security_score": sec_score,
            "security_label": sec_label
        }



    #######


    def _analyze_sbox_structure(self) -> Dict[str, Any]:
        """Analyze S-box structure and properties"""
        sbox_info = {
            "sbox_size": 4,  # Default for PRESENT (4x4 S-box)
            "sbox_defined": False,
            "sbox_nonlinearity": 0.5,  # Typical for PRESENT
            "sbox_entries": []
        }
        
        # Look for S-box definition in the content
        sbox_patterns = [
            r'sbox_table\s*=\s*\[([^\]]+)\]',
            r'sbox\s*=\s*\[([^\]]+)\]',
            r'sbox_table.*?=\s*"([^"]+)"'
        ]
        
        for pattern in sbox_patterns:
            match = re.search(pattern, self.content, re.DOTALL | re.IGNORECASE)
            if match:
                sbox_values = re.findall(r'0x[0-9A-Fa-f]+', match.group(1))
                if sbox_values:
                    sbox_info.update({
                        "sbox_defined": True,
                        "sbox_size": len(sbox_values),
                        "sbox_entries": sbox_values[:16]  # First 16 entries
                    })
                    break
        
        return sbox_info

    def _analyze_permutation_structure(self) -> Dict[str, Any]:
        """Analyze permutation layer structure"""
        perm_info = {
            "perm_defined": False,
            "perm_type": "bit_permutation",  # PRESENT uses bit permutation
            "perm_size": 64  # Default for PRESENT-64
        }
        
        # Look for permutation layer definitions
        perm_indicators = [
            r'p_layer',
            r'permutation',
            r'bit_permutation'
        ]
        
        for indicator in perm_indicators:
            if re.search(indicator, self.content, re.IGNORECASE):
                perm_info["perm_defined"] = True
                break
        
        # Try to extract permutation size from context
        if "64" in os.path.basename(self.thy_path):
            perm_info["perm_size"] = 64
        elif "128" in os.path.basename(self.thy_path):
            perm_info["perm_size"] = 128
            
        return perm_info

        

    def _contains_spn_operations(self, body: str) -> bool:
        """Check if function body contains SPN operations"""
        spn_indicators = [
            r'sbox',                    # S-box operations
            r'p_layer',                 # Permutation layer
            r'permutation',             # Permutations
            r'present_round',           # Round function
            r'extract_round_key',       # Key handling
            r'key_schedule',            # Key expansion
        ]
        
        for indicator in spn_indicators:
            if re.search(indicator, body, re.IGNORECASE):
                return True
        return False

    def _clean_function_body(self, body: str) -> str:
        """Clean function body for better parsing"""
        # Remove block comments
        body = re.sub(r'\(\*.*?\*\)', '', body, flags=re.DOTALL)
        # Remove line comments
        body = re.sub(r'--.*$', '', body, flags=re.MULTILINE)
        # Remove extra whitespace
        body = re.sub(r'\s+', ' ', body)
        return body.strip()


def extract_isabelle_definitions(content: str) -> List[Tuple[str, str]]:
    """
    Extract named definition/fun/function blocks with better pattern matching.
    """
    blocks: List[Tuple[str, str]] = []
    
    # More robust pattern for definitions
    patterns = [
        # definition name where "body"
        r'definition\s+([A-Za-z0-9_]+)\s*.*?\s*where\s*"([^"]*)"',
        # definition name = body
        r'definition\s+([A-Za-z0-9_]+)\s*=\s*([^;\n]+)',
        # fun/function with equations
        r'(fun|function)\s+([A-Za-z0-9_]+)\s*.*?\s*where\s*"([^"]*)"',
        # Simple pattern for any identifier followed by equals
        r'^([A-Za-z0-9_]+)\s*=\s*([^;\n]+)$'
    ]
    
    # Also look for pattern: name args = body
    lines = content.split('\n')
    current_def = None
    current_body = []
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # Check for definition start
        def_match = re.match(r'^(definition|fun|function)\s+([A-Za-z0-9_]+)', line)
        if def_match:
            if current_def and current_body:
                blocks.append((current_def, ' '.join(current_body)))
            current_def = def_match.group(2)
            current_body = []
            # Extract initial body if present
            if '=' in line or 'where' in line:
                body_part = line.split('=', 1)[-1] if '=' in line else line.split('where', 1)[-1]
                current_body.append(body_part.strip('" '))
        elif current_def and (line.startswith('|') or line.startswith('"') or '=' in line):
            # Continuation of definition
            current_body.append(line.strip('" '))
        elif current_def and (line.startswith('lemma') or line.startswith('theorem') or line.startswith('end')):
            # End of definition block
            if current_body:
                blocks.append((current_def, ' '.join(current_body)))
            current_def = None
            current_body = []
    
    # Don't forget the last definition
    if current_def and current_body:
        blocks.append((current_def, ' '.join(current_body)))
    
    # Also try the direct pattern matching
    for pattern in patterns:
        for match in re.finditer(pattern, content, re.DOTALL | re.MULTILINE):
            groups = match.groups()
            if len(groups) >= 2:
                # The last group is usually the body, the one before is the name
                if len(groups) == 2:
                    name, body = groups
                else:
                    name, body = groups[1], groups[2] if len(groups) > 2 else groups[1]
                
                body = body.strip()
                # Clean up the body
                if body.endswith('"'):
                    body = body[:-1].strip()
                if body.endswith(';'):
                    body = body[:-1].strip()
                
                # Avoid duplicates
                if not any(b[0] == name for b in blocks):
                    blocks.append((name, body))
    
    return blocks


# ----------------------------
# SecurityScorer (uses compute_security_score from cipher_profiles)
# ----------------------------
class SecurityScorer:
    def __init__(self, cipher_name: str, block_size: int, key_size: int, rounds: int):
        self.cipher_name = cipher_name
        self.block_size = block_size
        self.key_size = key_size
        self.rounds = rounds
        self.CIPHER_SEC_PARAMS = SecurityParams(self.cipher_name)
    
    def compute(self, variant_tag: str = None) -> Tuple[float, str]:
            # 1. Construct the lookup key based on the tag
            if variant_tag:
                lookup_key = (self.block_size, self.key_size, variant_tag)
            else:
                lookup_key = (self.block_size, self.key_size)
                
            # 2. Look up in ATTACK_DB
            attack_info = ATTACK_DB.get(self.cipher_name, {}).get(lookup_key, {})
    
            # If look up fails for "Low", try falling back to standard? 
            # No, if "Low" is specified but not in DB, we want it to use the params 
            # passed in (which should come from the modified .thy file rounds)
            
            if attack_info:
                # Use attack data
                rounds = attack_info.get('total_rounds', self.rounds)
                rounds_broken = attack_info.get('rounds_broken')
                attack_type = attack_info.get('attack_type')
                complexity = attack_info.get('complexity')
                attacks = {attack_type: complexity} if attack_type and complexity else {}
            else:
                # Fall back to profile data
                rounds = self.rounds
                rounds_broken = None
                attack_type = None
                attacks = {}
    
            score = compute_security_score(self.CIPHER_SEC_PARAMS, self.block_size, self.key_size, rounds, attacks, rounds_broken, attack_type)
            label = security_label_from_score(score)
            return score, label


# ----------------------------
# Extractor factory and runner
# ----------------------------
EXTRACTOR_MAP = {
    "Feistel": FeistelExtractor,
    "ARX": ARXExtractor,
    "SPN": SPNExtractor,
    "HIGHT_ARX": HIGHTExtractor
}

def build_ast_and_pdv_for_file(thy_path: str, profile_name: str) -> Optional[Dict[str, Any]]:
    """Top-level: determine family and run extractor, with error handling."""
    try:
        profile = CIPHER_PROFILES.get(profile_name)
        if not profile:
            raise ValueError(f"Unknown profile: {profile_name}")
        family = profile.get("family")
        extractor_cls = EXTRACTOR_MAP.get(family)
        
        if extractor_cls is None:
            raise ValueError(f"No extractor for family '{family}'")
        print(profile_name)
        extractor = extractor_cls(thy_path, profile_name)
        return extractor.extract()
    except Exception as e:
        print(f"Error processing {thy_path}: {e}")
        traceback.print_exc()
        return None


# Notebook-friendly runner
def main(input_dir: str, output_dir: str, cipher_name: str):
    """
    Run the extractor for all .thy files in input_dir that match the given cipher_name
    and write .json outputs to output_dir.
    """
    #from cipher_extractor import build_ast_and_pdv_for_file  # if in separate module adjust import
    import os, json

    os.makedirs(output_dir, exist_ok=True)
    thy_files = [f for f in os.listdir(input_dir) if f.endswith('.thy')]

    summary = []
    for f in thy_files:
        if cipher_name.lower() not in f.lower():
            continue
        path = os.path.join(input_dir, f)
        result = build_ast_and_pdv_for_file(path, cipher_name)
        if not result:
            continue
        outname = f.replace('.thy', '.json')
        outpath = os.path.join(output_dir, outname)
        with open(outpath, 'w', encoding='utf-8') as fo:
            json.dump(result, fo, indent=2)
        summary.append({"file": f, "cipher_variant": result.get("cipher_variant"), "security_label": result.get("security_label")})
        print(f"Processed {f} -> {outpath}")

    # write summary
    with open(os.path.join(output_dir, '_summary.json'), 'w', encoding='utf-8') as fo:
        json.dump(summary, fo, indent=2)
    print("Done. Summary saved.")




input_dir = "generated_thy_variants"
output_dir = "output_ast/"

# =============================================================================
# MAIN EXECUTION
# =============================================================================

if __name__ == "__main__":
    cipher_names = ['Simon', 'Speck', 'PRESENT','XTEA', 'LEA', 'Sparx', 'GIFT', 'Rectangle', 'Simeck','HIGHT', 'SKINNY']
    #cipher_names = ['SKINNY']
    for cipher_name in cipher_names:
        print(f'\n CIPHER: {cipher_name} \n\n')
        main(input_dir, output_dir+cipher_name, cipher_name)
