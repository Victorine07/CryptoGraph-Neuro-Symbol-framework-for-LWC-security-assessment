# cipher_profiles.py

"""
cipher_profiles.py
Cipher Profile definitions and Security Scoring logic.
This version supports Simon (Feistel), Speck (ARX), and PRESENT (SPN) ciphers,
and integrates realistic security scoring and labeling.
"""

import math
from dataclasses import dataclass
from typing import Dict, Any, Tuple

# ============================================================
# ATTACK DATABASE — known attack complexity for cipher variants
# ============================================================
ATTACK_DB = {
    "Simon": {
        (32, 64):   {'total_rounds': 32, 'rounds_broken': 24, 'attack_type': 'integral', 'complexity': 2**63},
        (48, 72):   {'total_rounds': 36, 'rounds_broken': 24, 'attack_type': 'linear_hull', 'complexity': 2**56},
        (48, 96):   {'total_rounds': 36, 'rounds_broken': 25, 'attack_type': 'linear_hull', 'complexity': 2**80},
        (64, 96):   {'total_rounds': 42, 'rounds_broken': 30, 'attack_type': 'linear_hull', 'complexity': 2**88},
        (64, 128):  {'total_rounds': 44, 'rounds_broken': 31, 'attack_type': 'linear_hull', 'complexity': 2**122},
        (96, 96):   {'total_rounds': 52, 'rounds_broken': 37, 'attack_type': 'linear_hull', 'complexity': 2**88},
        (96, 144):  {'total_rounds': 54, 'rounds_broken': 38, 'attack_type': 'linear_hull', 'complexity': 2**136},
        (128, 128): {'total_rounds': 68, 'rounds_broken': 49, 'attack_type': 'linear_hull', 'complexity': 2**120},
        (128, 192): {'total_rounds': 69, 'rounds_broken': 51, 'attack_type': 'linear_hull', 'complexity': 2**184},
        (128, 256): {'total_rounds': 72, 'rounds_broken': 53, 'attack_type': 'linear_hull', 'complexity': 2**248},
        # BROKEN ROUNDS TO DIFFERENTIATE FROM LOW SECURITY 
        # BROKEN VARIANTS
        # 12 rounds is fully broken (Rounds Broken >= Total Rounds)
        # Complexity is extremely low (e.g., 2^20 operations)
        #(32, 64, "Weak"):   {'total_rounds': 12, 'rounds_broken': 12, 'attack_type': 'differential', 'complexity': 2**20},
        (32, 64, "Broken"):   {'total_rounds': 12, 'rounds_broken': 12, 'attack_type': 'differential', 'complexity': 2**10},
        (48, 72, "Broken"):   {'total_rounds': 12, 'rounds_broken': 12, 'attack_type': 'differential', 'complexity': 2**10},
    },
    "Speck": {
        (32, 64):   {'total_rounds': 22, 'rounds_broken': 15, 'attack_type': 'differential', 'complexity': 2**63.39},
        (48, 72):   {'total_rounds': 22, 'rounds_broken': 16, 'attack_type': 'differential', 'complexity': 2**71.8},
        (48, 96):   {'total_rounds': 23, 'rounds_broken': 17, 'attack_type': 'differential', 'complexity': 2**95.8},
        (64, 96):   {'total_rounds': 26, 'rounds_broken': 19, 'attack_type': 'differential', 'complexity': 2**93.56},
        (64, 128):  {'total_rounds': 27, 'rounds_broken': 20, 'attack_type': 'differential', 'complexity': 2**125.56},
        (96, 96):   {'total_rounds': 28, 'rounds_broken': 20, 'attack_type': 'differential', 'complexity': 2**95.94},
        (96, 144):  {'total_rounds': 29, 'rounds_broken': 21, 'attack_type': 'differential', 'complexity': 2**143.94},
        (128, 128): {'total_rounds': 32, 'rounds_broken': 23, 'attack_type': 'differential', 'complexity': 2**125.35},
        (128, 192): {'total_rounds': 33, 'rounds_broken': 24, 'attack_type': 'differential', 'complexity': 2**189.35},
        (128, 256): {'total_rounds': 34, 'rounds_broken': 25, 'attack_type': 'differential', 'complexity': 2**253.35},
        # BROKEN ENTRIES
        # 9 rounds vs 15 rounds broken = 0 margin, instant break
        (32, 64, "Broken"): {'total_rounds': 9, 'rounds_broken': 9, 'attack_type': 'differential', 'complexity': 2**10},
        (48, 72, "Broken"): {'total_rounds': 9, 'rounds_broken': 9, 'attack_type': 'differential', 'complexity': 2**10},
    },
    "PRESENT": {
        (64, 40):   {'total_rounds': 8, 'rounds_broken': 6, 'attack_type': 'cryptanalytic', 'complexity': 2**60},
        (64, 80):   {'total_rounds': 31, 'rounds_broken': 26, 'attack_type': 'cryptanalytic', 'complexity': 2**95},
        (64, 128):  {'total_rounds': 31, 'rounds_broken': 26, 'attack_type': 'differential', 'complexity': 2**124},

    },
    "HIGHT": {
        # Standard (Medium Security)
        (64, 128):  {'total_rounds': 32, 'rounds_broken': 26, 'attack_type': 'biclique', 'complexity': 2**118},
        
        # === NEW SYNTHETIC ENTRIES ===
        
        # BROKEN: 12 Rounds.
        # Attack breaks 26 rounds. Margin = 12 - 26 = -14.
        # This is strictly BROKEN. Complexity is trivial (e.g. 2^20).
        (64, 128, "Broken"): {'total_rounds': 12, 'rounds_broken': 26, 'attack_type': 'impossible_differential', 'complexity': 2**20},

        # LOW: 28 Rounds.
        # Attack breaks 26 rounds. Margin = 28 - 26 = 2 rounds (Positive but thin).
        # Score will be penalized for low margin, resulting in LOW label.
        #(64, 128, "Low"): {'total_rounds': 28, 'rounds_broken': 26, 'attack_type': 'related_key', 'complexity': 2**100},
    },
    # === NEW CIPHERS ===
    "Simeck": {
        (32, 64):   {'total_rounds': 32, 'rounds_broken': 22, 'attack_type': 'differential', 'complexity': 2**60}, 
        (48, 96):   {'total_rounds': 36, 'rounds_broken': 28, 'attack_type': 'differential', 'complexity': 2**90},
        (64, 128):  {'total_rounds': 44, 'rounds_broken': 35, 'attack_type': 'differential', 'complexity': 2**120},
        (32, 64, "Broken"): {'total_rounds': 16, 'rounds_broken': 16, 'attack_type': 'differential', 'complexity': 2**10}, 
    },
    "XTEA": {
        (64, 128):  {'total_rounds': 64, 'rounds_broken': 36, 'attack_type': 'related_key', 'complexity': 2**120} ,
        # Note: XTEA full rounds are rarely broken, usually heavily reduced variants
        # 32 rounds (16 cycles) is broken
        (64, 128, "Broken"): {'total_rounds': 32, 'rounds_broken': 32, 'attack_type': 'related_key', 'complexity': 2**1},
    },
    "LEA": {
        (128, 128): {'total_rounds': 24, 'rounds_broken': 16, 'attack_type': 'differential', 'complexity': 2**120},
        #(128, 192): {'total_rounds': 28, 'rounds_broken': 18, 'attack_type': 'differential', 'complexity': 2**180},
        #(128, 256): {'total_rounds': 32, 'rounds_broken': 20, 'attack_type': 'differential', 'complexity': 2**240},
        # BROKEN ENTRY (11 Rounds)
        # Deeply broken. 
        #(128, 128, "Broken"): {'total_rounds': 11, 'rounds_broken': 11, 'attack_type': 'differential', 'complexity': 2**1},

        # LOW SECURITY ENTRY (16 Rounds)
        # 16 rounds is exactly where known attacks stop. Margin is near 0.
        # This should yield a "Low" label, but not "Broken".
        #(128, 128, "Low"): {'total_rounds': 16, 'rounds_broken': 12, 'attack_type': 'differential', 'complexity': 2**70},
    },
    "GIFT": {
        (64, 128):  {'total_rounds': 28, 'rounds_broken': 20, 'attack_type': 'linear', 'complexity': 2**120},
        (128, 128): {'total_rounds': 40, 'rounds_broken': 26, 'attack_type': 'linear', 'complexity': 2**120},
        (64, 128, "Broken"): {'total_rounds': 10, 'rounds_broken': 10, 'attack_type': 'linear', 'complexity': 2**1},


        # High (Standard)
        #(64, 128):  {'total_rounds': 28, 'rounds_broken': 20, 'attack_type': 'linear', 'complexity': 2**120},
        # Low (19 rounds vs 20 broken = 0 margin, but complexity is still high-ish, so score ~3-4)
        (64, 128, "Low"): {'total_rounds': 22, 'rounds_broken': 20, 'attack_type': 'linear', 'complexity': 2**63},
        
        
    },
    "Rectangle": {
        (64, 80):   {'total_rounds': 25, 'rounds_broken': 18, 'attack_type': 'differential', 'complexity': 2**78},
        #(64, 128):  {'total_rounds': 25, 'rounds_broken': 19, 'attack_type': 'differential', 'complexity': 2**126},
        (64, 80, "Broken"): {'total_rounds': 10, 'rounds_broken': 10, 'attack_type': 'differential', 'complexity': 2**10},

        (64, 80, "Low"): {'total_rounds': 18, 'rounds_broken': 18, 'attack_type': 'differential', 'complexity': 2**60},
    },
    
    "Sparx": {
        (64, 128):  {'total_rounds': 24, 'rounds_broken': 16, 'attack_type': 'differential', 'complexity': 2**120},
        (128, 128): {'total_rounds': 32, 'rounds_broken': 22, 'attack_type': 'differential', 'complexity': 2**120},
        (128, 256): {'total_rounds': 40, 'rounds_broken': 20, 'attack_type': 'zero_correlation', 'complexity': 2**190},
        (64, 128, "Broken"): {'total_rounds': 6, 'rounds_broken': 6, 'attack_type': 'differential', 'complexity': 2**4},

        (64, 128, "Low"): {'total_rounds': 12, 'rounds_broken': 12, 'attack_type': 'differential', 'complexity': 2**100},
    
    },
    "SKINNY": {
        # High Security: 36 Rounds
        # Best attacks break ~22-26 rounds. Complexity 2^128.
        (64, 128): {'total_rounds': 36, 'rounds_broken': 24, 'attack_type': 'rectangle', 'complexity': 2**126},
        
        # Broken Variant: 12 Rounds
        # Deeply broken. Complexity is trivial.
        (64, 64): {'total_rounds': 32, 'rounds_broken': 24, 'attack_type': 'integral', 'complexity': 2**90},
        (64, 128, "Broken"): {'total_rounds': 6, 'rounds_broken': 6, 'attack_type': 'integral', 'complexity': 2**4},
    },
}

# ============================================================
# SECURITY SCORING SYSTEM (REALISTIC MODEL)
# ============================================================

@dataclass
class SecurityParams:
    """Dynamic security parameters that adjust based on cipher family."""
    
    # STEP 1: Define attributes at the class level.
    # The dataclass will automatically create an __init__ that accepts `cipher_name`.
    cipher_name: str = None
    #_max_params: Dict[str, int] = field(init=False, repr=False)  # Don't include in init
    

    # STEP 2: Move initialization logic to __post_init__.
    # This special method runs right after the dataclass's own __init__ is finished.
    def __post_init__(self):
        """This method is called after the dataclass-generated __init__."""
        self._max_params = self._calculate_max_params()
    
    
    def _calculate_max_params(self) -> Dict[str, int]:
        """Calculate maximum security parameters for the given cipher family."""
        if not self.cipher_name:
            # Default fallback values
            return {
                "max_rounds": 72,
                "max_key_size": 256, 
                "max_block_size": 128
            }
        
        
        # Cipher-specific maximums based on known variants
        cipher_maxima = {
            "Simon":     {"max_rounds": 72, "max_key_size": 256, "max_block_size": 128},
            "Speck":     {"max_rounds": 34, "max_key_size": 256, "max_block_size": 128},
            "PRESENT":   {"max_rounds": 31, "max_key_size": 128, "max_block_size": 64},
            "HIGHT":     {"max_rounds": 32, "max_key_size": 128, "max_block_size": 64},
            "Simeck":    {"max_rounds": 44, "max_key_size": 128, "max_block_size": 64},
            "XTEA":      {"max_rounds": 64, "max_key_size": 128, "max_block_size": 64},
            "LEA":       {"max_rounds": 32, "max_key_size": 256, "max_block_size": 128},
            "GIFT":      {"max_rounds": 40, "max_key_size": 128, "max_block_size": 128},
            "Rectangle": {"max_rounds": 25, "max_key_size": 128, "max_block_size": 64},
            "Sparx":     {"max_rounds": 32, "max_key_size": 256, "max_block_size": 128},
        }

        return cipher_maxima.get(self.cipher_name, {
            "max_rounds": 72,
            "max_key_size": 256,
            "max_block_size": 128
        })

        
    @property
    def max_rounds(self) -> int:
        return self._max_params["max_rounds"]
    
    @property
    def max_key_size(self) -> int:
        return self._max_params["max_key_size"]
    
    @property
    def max_block_size(self) -> int:
        return self._max_params["max_block_size"]
    
    def get_params(self) -> Dict[str, int]:
        """Return all parameters as a dictionary."""
        return self._max_params.copy()
    
    def __str__(self) -> str:
        return (f"(max_rounds={self.max_rounds}, "
                f"max_key_size={self.max_key_size}, "
                f"max_block_size={self.max_block_size})")
        
DEFAULT_PARAMS = SecurityParams()


def get_attack_severity(attack_type: str) -> float:
    """
    Return severity factor for different attack types.
    lower values = more concerning attacks.
    """
    severity_map = {
        'brute_force': 1.0,        # Expected baseline
        'linear': 0.9,             # Moderate concern
        'linear_hull': 0.9,        # Moderate concern
        'differential': 0.8,       # Moderate concern  
        'integral': 0.7,           # Moderate concern
        'zero_correlation': 0.6,   # Less common but serious
        'impossible_differential': 0.6,  # Advanced but serious
        'biclique': 0.2,           # Advanced attack
        'related_key': 0.9,        # Very concerning
        'meet_in_middle': 0.8,     # Concerning
        'algebraic': 0.4,          # Theoretical, less practical
        'cryptanalytic': 0.7,      # General cryptanalysis
        None: 1.0                  # No known attacks = best case
    }
    return severity_map.get(attack_type, 0.7)


def compute_security_score(params: SecurityParams, block_size: int, key_size: int,
                           rounds: int, attacks: Dict[str, int], 
                           rounds_broken: int = None, attack_type: str = None) -> float:
    """
    Revised scoring: Prioritizes Complexity for valid ciphers, punishes Broken ones heavily.
    """
    # 1. Calculate Security Margin
    if rounds_broken is not None and rounds > 0:
        security_margin = (rounds - rounds_broken) / rounds
    else:
        security_margin = 0.5 # Default conservative margin

    # 2. Design Strength (Block/Key size contribution) - Max 10.0
    # Standardized to 128-bit = 1.0. 
    # This ensures Simon-32 (small block) gets a lower base design score than Simon-128.
    design_score = (0.6 * (key_size / 256) + 0.4 * (block_size / 128))

    # 3. Attack Security Score
    if attacks:
        # Logarithmic complexity (e.g., 2^120 -> 120)
        complexity_bits = math.log2(min(attacks.values()))
        
        # Normalize: 128 bits is considered "Perfect" (1.0) for lightweight
        base_security = min(1.0, complexity_bits / 128)
        
        if security_margin <= 0:
            # BROKEN: Massive penalty. You only keep 20% of your score.
            # Example: Simon Broken (2^20) -> 0.15 * 0.2 = 0.03 (Destroyed)
            margin_multiplier = 0.2
        else:
            # SECURE: Light penalty. You keep 80% + a bonus for your margin.
            # Example: Simon 128 (margin 0.28) -> 0.8 + (0.2 * 0.28) = 0.85 (High Score preserved)
            margin_multiplier = 0.8 + (0.2 * security_margin)
            
        security_component = base_security * margin_multiplier
    else:
        # No attacks? Assume theoretical max security based on key size
        security_component = min(1.0, key_size / 128)

    # 4. Attack Severity (unchanged)
    severity_factor = get_attack_severity(attack_type)

    # 5. Final Weights
    # Security (Complexity) is the most important factor (70%)
    # Design (Block/Key Size) is secondary (20%)
    # Severity is minor (10%)
    final_score = (0.7 * security_component + 0.2 * design_score + 0.1 * severity_factor) * 10.0
    
    return round(min(10.0, final_score), 2)

    
def security_label_from_score(score: float) -> str:
    if score < 2.0:       # New threshold for BROKEN
        return "broken"
    if score < 5.0:
        return "low"
    elif score < 7:
        return "medium"
    return "high"
    


# ============================================================
# CIPHER PROFILES
# ============================================================

CIPHER_PROFILES = {
    "Simon": {
        "family": "Feistel",
        "variants": {
            "Simon32_64":  {"block_size": 32, "key_size": 64, "rounds": 32},
            "Simon48_72":  {"block_size": 48, "key_size": 72, "rounds": 36},
            "Simon48_96":  {"block_size": 48, "key_size": 96, "rounds": 36},
            "Simon64_96":  {"block_size": 64, "key_size": 96, "rounds": 42},
            "Simon64_128": {"block_size": 64, "key_size": 128, "rounds": 44},
            "Simon96_96":  {"block_size": 96, "key_size": 96, "rounds": 52},
            "Simon96_144": {"block_size": 96, "key_size": 144, "rounds": 54},
            "Simon128_128": {"block_size": 128, "key_size": 128, "rounds": 68},
            "Simon128_192": {"block_size": 128, "key_size": 192, "rounds": 69},
            "Simon128_256": {"block_size": 128, "key_size": 256, "rounds": 72},
            # BROKEN ROUNDS, TO DIFFERENTIATE FROM LOW SECURITY
            "Simon32_64_Broken": {"block_size": 32, "key_size": 64, "rounds": 12}, 
            "Simon48_72_Broken": {"block_size": 48, "key_size": 72, "rounds": 12},
            
        }
    },
    "Speck": {
        "family": "ARX",
        "variants": {
            "Speck32_64":  {"block_size": 32, "key_size": 64, "rounds": 22},
            "Speck48_72":  {"block_size": 48, "key_size": 72, "rounds": 22},
            "Speck48_96":  {"block_size": 48, "key_size": 96, "rounds": 23},
            "Speck64_96":  {"block_size": 64, "key_size": 96, "rounds": 26},
            "Speck64_128": {"block_size": 64, "key_size": 128, "rounds": 27},
            "Speck96_96":  {"block_size": 96, "key_size": 96, "rounds": 28},
            "Speck96_144": {"block_size": 96, "key_size": 144, "rounds": 29},
            "Speck128_128": {"block_size": 128, "key_size": 128, "rounds": 32},
            "Speck128_192": {"block_size": 128, "key_size": 192, "rounds": 33},
            "Speck128_256": {"block_size": 128, "key_size": 256, "rounds": 34},
            # === NEW BROKEN VARIANTS ===
            # Speck 32/64 Broken (9 rounds is standard broken benchmark)
            "Speck32_64_Broken":  {"block_size": 32, "key_size": 64, "rounds": 9},
            # Speck 48/72 Broken (9 rounds matches the 32/64 pattern)
            "Speck48_72_Broken":  {"block_size": 48, "key_size": 72, "rounds": 9},
        }
    },
    "PRESENT": {
        "family": "SPN",
        "variants": {
            "PRESENT64_40":  {"block_size": 64, "key_size": 40, "rounds": 8},
            "PRESENT64_80":  {"block_size": 64, "key_size": 80, "rounds": 31},
            "PRESENT64_128": {"block_size": 64, "key_size": 128, "rounds": 31},
        }
    },
    "HIGHT": {
        "family": "HIGHT_ARX",
        "variants": {
            # Standard (Medium/High borderline)
            "HIGHT64_128": {"block_size": 64, "key_size": 128, "rounds": 32},
            
            # === ADD THESE ===
            # Broken: Attacks break ~26 rounds. 
            # If we set rounds=12, Margin is NEGATIVE -> BROKEN.
            "HIGHT64_128_Broken": {"block_size": 64, "key_size": 128, "rounds": 12}, 
            
            # Low: Positive margin but reduced complexity
            #"HIGHT64_128_Low": {"block_size": 64, "key_size": 128, "rounds": 28},
        }
    },
    
    # "HIGHT": {
    #     "family": "HIGHT_ARX",
    #     "variants": {
    #         "HIGHT64_128": {"block_size": 64, "key_size": 128, "rounds": 32},
    #     }
    # },
    # === NEW CIPHERS ===
    "Simeck": {
        "family": "Feistel",
        "variants": {
            "Simeck32_64":  {"block_size": 32, "key_size": 64, "rounds": 32},
            "Simeck48_96":  {"block_size": 48, "key_size": 96, "rounds": 36},
            "Simeck64_128": {"block_size": 64, "key_size": 128, "rounds": 44},
            # NEW BROKEN VARIANT
            "Simeck32_64_Broken": {"block_size": 32, "key_size": 64, "rounds": 16}, 
        }
    },
    "XTEA": {
        "family": "Feistel",
        "variants": {
            "XTEA64_128": {"block_size": 64, "key_size": 128, "rounds": 64},
            # NEW BROKEN VARIANT (32 Rounds = 16 Cycles)
            "XTEA64_128_Broken": {"block_size": 64, "key_size": 128, "rounds": 16},
        }
    },
    "LEA": {
        "family": "ARX",
        "variants": {
            "LEA128_128": {"block_size": 128, "key_size": 128, "rounds": 24},
            #"LEA128_192": {"block_size": 128, "key_size": 192, "rounds": 28},
            #"LEA128_256": {"block_size": 128, "key_size": 256, "rounds": 32},
            
            # === NEW VARIANTS ===
            # Broken Variant (11 Rounds - Highly insecure)
            #"LEA128_128_Broken": {"block_size": 128, "key_size": 128, "rounds": 11},
            
            # Low/Medium Security Variant (16 Rounds - Weak but not fully broken immediately)
            # This fills the gap between "Broken" and "High"
            #"LEA128_128_Low": {"block_size": 128, "key_size": 128, "rounds": 16},
        }
    },
    "GIFT": {
        "family": "SPN",
        "variants": {
            "GIFT64_128":  {"block_size": 64, "key_size": 128, "rounds": 28},
            "GIFT128_128": {"block_size": 128, "key_size": 128, "rounds": 40},
            # BROKEN VARIANT
            "GIFT64_128_Broken": {"block_size": 64, "key_size": 128, "rounds": 10},
            
            "GIFT64_128_Low": {"block_size": 64, "key_size": 128, "rounds": 19},     # Low
            
        }
    },

    "Rectangle": {
        "family": "SPN",
        "variants": {
            "Rectangle64_80":  {"block_size": 64, "key_size": 80, "rounds": 25},
            #"Rectangle64_128": {"block_size": 64, "key_size": 128, "rounds": 25},
            # BROKEN VARIANT
            "Rectangle64_80_Broken": {"block_size": 64, "key_size": 80, "rounds": 10},

            "Rectangle64_80_Low": {"block_size": 64, "key_size": 80, "rounds": 18},    # Low
        }
    },
    "Sparx": {
        "family": "SPN", # Structurally SPN, though uses ARX components
        "variants": {
            "Sparx64_128":  {"block_size": 64, "key_size": 128, "rounds": 24},
            "Sparx128_128": {"block_size": 128, "key_size": 128, "rounds": 32},
            "Sparx128_256": {"block_size": 128, "key_size": 256, "rounds": 40},
            # BROKEN VARIANT
            "Sparx64_128_Low": {"block_size": 64, "key_size": 128, "rounds": 12},    # Low
            "Sparx64_128_Broken": {"block_size": 64, "key_size": 128, "rounds": 6},  # Broken
        }
    },
    "SKINNY": {
        "family": "SPN",
        "variants": {
            # Standard (High Security)
            "SKINNY_64_128": {"block_size": 64, "key_size": 128, "rounds": 36},
            
            # Synthetic Broken (Negative Security Margin)
            # 12 rounds is well within the attackable range (~22 rounds)
            "SKINNY_64_128_Broken": {"block_size": 64, "key_size": 128, "rounds": 6},
        }
    },
}

# ============================================================
# HELPER — get security info for a given cipher variant
# ============================================================

def get_cipher_security_info(cipher_name: str, variant_name: str) -> Dict[str, Any]:
    """Return cipher configuration enriched with security score and label."""

    
    cipher_entry = CIPHER_PROFILES.get(cipher_name)
    if not cipher_entry:
        raise ValueError(f"Unknown cipher: {cipher_name}")

    variant = cipher_entry["variants"].get(variant_name)
    if not variant:
        raise ValueError(f"Unknown variant: {variant_name}")

    block_size = variant["block_size"]
    key_size = variant["key_size"]
    profile_rounds = variant["rounds"]

    # Get enhanced attack data
    # attack_info = ATTACK_DB.get(cipher_name, {}).get((block_size, key_size), {})

    # === UPDATED LOOKUP LOGIC ===
    if "Broken" in variant_name:
        attack_info = ATTACK_DB.get(cipher_name, {}).get((block_size, key_size, "Broken"), {})
    elif "Low" in variant_name:
        # Check for specific "Low" tag (used for LEA)
        attack_info = ATTACK_DB.get(cipher_name, {}).get((block_size, key_size, "Low"), {})
        # If no specific Low entry exists, fall back to standard (it might be Low by default like Simon32)
        if not attack_info:
             attack_info = ATTACK_DB.get(cipher_name, {}).get((block_size, key_size), {})
    else:
        attack_info = ATTACK_DB.get(cipher_name, {}).get((block_size, key_size), {})
    # ========================
    
    
    if attack_info:
        # Use attack data if available
        rounds = attack_info.get('total_rounds', profile_rounds)
        rounds_broken = attack_info.get('rounds_broken')
        attack_type = attack_info.get('attack_type')
        complexity = attack_info.get('complexity')
        attacks = {attack_type: complexity} if attack_type and complexity else {}
    else:
        # Fall back to profile data
        rounds = profile_rounds
        rounds_broken = None
        attack_type = None
        attacks = {}
    
    params = SecurityParams(cipher_name)
    
    # Use enhanced security scoring
    score = compute_security_score(
        params, block_size, key_size, rounds,
        attacks, rounds_broken, attack_type
    )
    label = security_label_from_score(score)

    return {
        "cipher_name": cipher_name,
        "variant": variant_name,
        "family": cipher_entry["family"],
        "block_size": block_size,
        "key_size": key_size,
        "rounds": rounds,
        "rounds_broken": rounds_broken,
        "security_margin": (rounds - rounds_broken) / rounds if rounds_broken else None,
        "attack_type": attack_type,
        "security_score": score,
        "security_label": label
    }, params



    