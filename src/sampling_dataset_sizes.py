# ----------------------------
# Data Sampling for Dataset Balance
# ----------------------------

import os

import json
import random
from collections import defaultdict
from typing import List, Dict, Any
import numpy as np

random.seed(42)


FLAG = 0

class CipherDataSampler:
    def __init__(self, input_base_dir: str, output_base_dir: str, delta_percent: float = 0.2):
        random.seed(42)
        np.random.seed(42)
        self.input_base_dir = input_base_dir
        self.output_base_dir = output_base_dir
        self.delta_percent = delta_percent
        self.label_mapping = {'broken': 0, 'low': 1, 'medium': 2, 'high': 3}
        self.reverse_label_mapping = {v: k for k, v in self.label_mapping.items()}
        

    # ----------------------------
    # Loading & Label Standardizing
    # ----------------------------
    def load_all_json_files(self) -> List[Dict[str, Any]]:
        all_files = []
        cipher_dirs = [
            d for d in os.listdir(self.input_base_dir)
            if os.path.isdir(os.path.join(self.input_base_dir, d))
        ]

        for cipher_dir in cipher_dirs:
            cipher_path = os.path.join(self.input_base_dir, cipher_dir)
            json_files = [f for f in os.listdir(cipher_path) if f.endswith(".json")]
            for json_file in json_files:
                file_path = os.path.join(cipher_path, json_file)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        data["file_source"] = file_path
                        data["cipher"] = cipher_dir
                        # make sure cipher_variant exists (fallback to file name without .json)
                        if "cipher_variant" not in data:
                            base = os.path.splitext(json_file)[0]
                            data["cipher_variant"] = base
                        all_files.append(data)

                        
                        # CHECK FOR LEAKAGE
                        json_str = json.dumps(data).lower()
                        forbidden_terms = ["simon_", "speck_", "present_", "simeck_", "lea_", "hight_", "xtea_", "sparx_", "rectangle_"]
                    
                        # We ignore the 'cipher_variant' metadata field, check only nodes/functions
                        # (Simple way: check if forbidden term appears in "label": "...")
                        for node in data.get("nodes", []):
                            label = node.get("label", "").lower()
                            if any(term in label for term in forbidden_terms):
                                raise ValueError(f"CRITICAL SECURITY FAIL: Anonymization failed in {json_file}. Found '{label}'")
                                
                except Exception as e:
                    print(f"X -- Error loading {file_path}: {e}")

                    
        print(f" OK -- Loaded {len(all_files)} total files from {len(cipher_dirs)} ciphers.")
        return all_files

    def standardize_labels(self, data_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        for data in data_list:
            label = data.get("security_label", "low")
            if isinstance(label, str):
                data["standardized_label"] = self.label_mapping.get(label.lower(), 0)
            else:
                data["standardized_label"] = int(label)
        return data_list

    # ----------------------------
    # Build structure: cipher -> variant -> list(files)
    # Each file should indicate whether it's augmented
    # ----------------------------
    def build_cipher_variant_index(self, data_list: List[Dict[str, Any]]) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
        idx = defaultdict(lambda: defaultdict(list))
        for d in data_list:
            cipher = d.get("cipher", "unknown")
            variant = d.get("cipher_variant", "unknown_variant")
            idx[cipher][variant].append(d)
        return idx

    # ----------------------------
    # Utility: gather variant->label mapping (assume variant's label = label of original file)
    # If multiple originals exist (rare), choose the non-augmented one as canonical.
    # ----------------------------
    def variant_label(self, files: List[Dict[str, Any]]) -> int:
        # prefer a non-augmented file's label as the variant's label
        for f in files:
            if not f.get("pdv", {}).get("augmented", False):
                return f.get("standardized_label", 0)
        # otherwise return first file label
        return files[0].get("standardized_label", 0)

    # ----------------------------
    # Core algorithm: per-cipher sampling guided by samples_per_variant (applied to smallest-class variants)
    # ----------------------------
    def sample_cipher_for_samples_per_variant(self, variants: Dict[str, List[Dict[str, Any]]],
                                              samples_per_variant: int, FLAG=FLAG) -> List[Dict[str, Any]]:
        """
        variants: dict variant_name -> list[file dicts]
        Goal:
          - Determine variant counts per class
          - baseline = min_variant_count * samples_per_variant
          - baseline_with_delta = baseline + randint(0, int(baseline * delta_percent))
          - For each class:
              target_files = max(number_of_original_files_in_class, baseline_with_delta)
              select: all originals first, then add augmented files by variant up to samples_per_variant per variant
        Returns list of selected file dicts for the cipher.
        """
        # Organize variants by class label
        class_variants = defaultdict(list)  # label -> list of variant names
        variant_files = variants  # variant_name -> list of files

        # Build per-variant canonical label and per-variant split(originals, augmented)
        variant_meta = {}
        for vname, files in variant_files.items():
            label = self.variant_label(files)
            # separate originals vs augmented for this variant
            originals = [f for f in files if not f.get("pdv", {}).get("augmented", False)]
            augmented = [f for f in files if f.get("pdv", {}).get("augmented", False)]
            variant_meta[vname] = {"label": label, "originals": originals, "augmented": augmented}
            class_variants[label].append(vname)

        # If some class has zero variants, skip it
        classes_present = list(class_variants.keys())
        if not classes_present:
            return []
            
        FLAG += 1
        # min number of variants across present classes (we consider only classes that appear)
        min_variant_count = min(len(class_variants[c]) for c in classes_present)

        # baseline files = min_variant_count * samples_per_variant
        baseline = min_variant_count * samples_per_variant
        # add-only delta
        add_delta = random.randint(0, max(1, int(baseline * self.delta_percent)))
        add_delta2 = max(FLAG%2, add_delta)
         
        baseline_with_delta = baseline  + add_delta

        selected_files = []

        # For each class, compute target files and select
    


        
        # For each class, compute target files and select
        for label in classes_present:
            variant_names = class_variants[label]
            # number of originals available in class (one per variant typically)
            originals_list = []
            for v in variant_names:
                originals_list.extend(variant_meta[v]["originals"])

            num_original_files = len(originals_list)  # typically equals number of variants for this class

            # target_files for this class: at least baseline_with_delta, but never below num_original_files
            target_files = max(num_original_files, baseline_with_delta)

            # But cap target_files by total available files in this class
            total_available = num_original_files + sum(len(variant_meta[v]["augmented"]) for v in variant_names)
            target_files = min(target_files, total_available)

            # Step 1: include all originals (preserve originals)
            selected_class_files = list(originals_list)

            # Step 2: if we need more, add augmented files while respecting per-variant per-limit
            needed = target_files - len(selected_class_files)
            if needed > 0:
                # For fairness, iterate variants in round-robin order adding up to per-variant limit:
                # Each variant may contribute up to (samples_per_variant - selected_from_that_variant)
                per_variant_selected = {v: 0 for v in variant_names}
                # initialize per-variant selected count from originals (if original from that variant included)
                for v in variant_names:
                    # if variant had an original and it's included, count it
                    if variant_meta[v]["originals"]:
                        per_variant_selected[v] = min(1, samples_per_variant)  # original counted as one
                # gather pools of augmented per variant
                aug_pools = {v: list(variant_meta[v]["augmented"]) for v in variant_names}

                # round-robin across variants to avoid concentrating all added files in a single variant
                variant_cycle = variant_names.copy()
                vi = 0
                iteration_count = 0
                max_iterations = len(variant_cycle) * 100  # Safety limit
                
                # print(f"    [DEBUG] Starting round-robin selection, max_iterations={max_iterations}")
                
                # FIX: Create a list of variants that can still contribute
                active_variants = [v for v in variant_cycle 
                                  if per_variant_selected[v] < samples_per_variant and aug_pools[v]]

 
                while needed > 0 and active_variants and iteration_count < max_iterations:
                    v = active_variants[vi % len(active_variants)]
                    vi += 1
                    iteration_count += 1
                    
                    # This condition should always be true because of active_variants filtering
                    if per_variant_selected[v] < samples_per_variant and aug_pools[v]:
                        selected_class_files.append(aug_pools[v].pop(0))
                        per_variant_selected[v] += 1
                        needed -= 1
                        # print(f"    [DEBUG] Iteration {iteration_count}: Added from variant {v}, needed={needed}")
                    
                    # Update active_variants - remove variants that can no longer contribute
                    active_variants = [v for v in active_variants 
                                      if per_variant_selected[v] < samples_per_variant and aug_pools[v]]
                    
                    # Safety check - if we're stuck, break
                    if iteration_count >= max_iterations:
                        print(f"    [WARNING] Reached max iterations ({max_iterations}), breaking loop")
                        break
                
                # print(f"    [DEBUG] After round-robin: needed={needed}, active_variants={len(active_variants)}")
                
                # if still needed (rare), try adding remaining augmented from any variant ignoring per-variant cap
                if needed > 0:
                    leftover = []
                    for v in variant_names:
                        leftover.extend(aug_pools[v])
                    if leftover:
                        to_take = min(needed, len(leftover))
                        selected_class_files.extend(leftover[:to_take])
                        needed -= to_take

            # done for this class: add to global selection
            selected_files.extend(selected_class_files)

        # end for each class
        return selected_files

    # ----------------------------
    # Main multi-size generation (per-variant sampling but balancing via baseline)
    # ----------------------------
    def generate_datasets_for_variant_sizes(self, samples_per_variant_sizes: List[int], FLAG=FLAG):
        all_data = self.standardize_labels(self.load_all_json_files())
        # index: cipher -> variant -> list(files)
        cipher_variant_index = defaultdict(dict)
        raw_index = self.build_cipher_variant_index(all_data)
        for cipher, variants in raw_index.items():
            for vname, files in variants.items():
                cipher_variant_index[cipher][vname] = files

        for size in samples_per_variant_sizes:
            print(f"\n ### Generating dataset for samples_per_variant = {size} ###")
            output_dir = os.path.join(self.output_base_dir, f"samples_per_variant_{size}")
            os.makedirs(output_dir, exist_ok=True)
            # print("FOLDER CREATED")

            for cipher, variants in cipher_variant_index.items():
                FLAG +=1
                cipher_dir = os.path.join(output_dir, cipher)
                os.makedirs(cipher_dir, exist_ok=True)
                # print( "folder created :", cipher_dir ) 

                sampled_files = self.sample_cipher_for_samples_per_variant(variants, size )
                # print( "fALL SAMPLE FILES CREATED:" ) 
                

                # Save all samples for this cipher (no subfolders per class)
                for i, sample in enumerate(sampled_files):
                    if "file_source" in sample:
                        # print( "fALL SAMPLE FILES CREATED:" ) 
                        del sample["file_source"]
                    label_name = self.reverse_label_mapping[sample["standardized_label"]]
                    is_aug = "_aug" if sample.get("pdv", {}).get("augmented", False) else ""
                    variant = sample.get("cipher_variant", f"{cipher}_unknown")
                    filename = f"{variant}_{label_name}{is_aug}_{i:03d}.json"
                    filepath = os.path.join(cipher_dir, filename)
                    with open(filepath, "w", encoding="utf-8") as f:
                        json.dump(sample, f, indent=2)

                print(f"  - {cipher}: saved {len(sampled_files)} files → {cipher_dir}")

            print(f" OK -- Finished dataset for {size} samples per variant → {output_dir}")

# ----------------------------
# Usage 
# ----------------------------
if __name__ == "__main__":
    sampler = CipherDataSampler(
        input_base_dir="augmented_data",
        output_base_dir="sampled_data_variant_based_balanced",
        delta_percent=0.2
    )

    # Different sizes you want per variant (applied to smallest-class variants)
    samples_per_variant_sizes = [1, 2,3,4, 5, 6, 7, 8,9, 10 ]
    sampler.generate_datasets_for_variant_sizes(samples_per_variant_sizes)
    