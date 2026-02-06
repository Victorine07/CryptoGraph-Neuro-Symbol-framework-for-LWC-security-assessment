import os

def create_broken_variant(original_path, new_path, original_rounds, new_rounds):
    with open(original_path, 'r') as f:
        content = f.read()
    
    # 1. Replace the rounds check in the code
    # e.g., "if i ≥ 32" becomes "if i ≥ 12"
    content = content.replace(f"if i ≥ {original_rounds}", f"if i ≥ {new_rounds}")
    
    # 2. Replace the measure function for termination proof
    # e.g., "measure (λ(keys, i). 32 - i)"
    content = content.replace(f"{original_rounds} - i", f"{new_rounds} - i")
    content = content.replace(f"{original_rounds} - n", f"{new_rounds} - n") # For recursive definitions
    
    # 3. Update the Theory Name
    original_name = os.path.basename(original_path).replace(".thy", "")
    new_name = os.path.basename(new_path).replace(".thy", "")
    content = content.replace(f"theory {original_name}", f"theory {new_name}")
    
    with open(new_path, 'w') as f:
        f.write(content)
    print(f"Created {new_path} ({new_rounds} rounds)")

# DEFINE YOUR PATHS HERE
input_dir = "generated_thy_variants" 

# 1. Simon 32/64 Broken (12 Rounds)
create_broken_variant(f"{input_dir}/Simon_32_64.thy", f"{input_dir}/Simon_32_64_Broken.thy", 32, 12)

# 2. Simon 48/72 Broken (12 Rounds)
create_broken_variant(f"{input_dir}/Simon_48_72.thy", f"{input_dir}/Simon_48_72_Broken.thy", 36, 12)

# 3. Simeck 32/64 Broken (16 Rounds)
# Note: Ensure you have Simeck_32_64.thy first!
if os.path.exists(f"{input_dir}/Simeck_32_64.thy"):
    create_broken_variant(f"{input_dir}/Simeck_32_64.thy", f"{input_dir}/Simeck_32_64_Broken.thy", 32, 16)

# 4. XTEA 64/128 Broken (16 Rounds)
# Note: XTEA uses "cycles", so check the variable name in your thy file. 
# If it says "xtea_num_cycles = 32", this script needs a slight tweak or you edit manually.
if os.path.exists(f"{input_dir}/xtea_64_128.thy"):
    with open(f"{input_dir}/xtea_64_128.thy", 'r') as f:
        xtea = f.read()
    xtea = xtea.replace("xtea_num_cycles = 32", "xtea_num_cycles = 8") # 8 cycles = 16 rounds
    xtea = xtea.replace("theory xtea_64_128", "theory xtea_64_128_Broken")
    with open(f"{input_dir}/xtea_64_128_Broken.thy", 'w') as f:
        f.write(xtea)
    print("Created XTEA Broken")


# 5. Speck 32/64 Broken (9 Rounds)
# Speck uses: if i ≥ (22 - 1)
if os.path.exists(f"{input_dir}/Speck_32_64.thy"):
    with open(f"{input_dir}/Speck_32_64.thy", 'r') as f:
        speck = f.read()
    # Replace the loop condition
    speck = speck.replace("if i ≥ (22 - 1)", "if i ≥ (9 - 1)")
    # Replace the termination measure
    speck = speck.replace("21 - i", "8 - i") 
    speck = speck.replace("theory Speck_32_64", "theory Speck_32_64_Broken")
    with open(f"{input_dir}/Speck_32_64_Broken.thy", 'w') as f:
        f.write(speck)
    print("Created Speck 32/64 Broken")


# 7. Speck 48/72 Broken (9 Rounds)
if os.path.exists(f"{input_dir}/Speck_48_72.thy"):
    with open(f"{input_dir}/Speck_48_72.thy", 'r') as f:
        content = f.read()
    # Speck 48/72 uses 22 rounds standard
    content = content.replace("if i ≥ (22 - 1)", "if i ≥ (9 - 1)")
    # Measure function 
    content = content.replace("21 - i", "8 - i") 
    content = content.replace("theory Speck_48_72", "theory Speck_48_72_Broken")
    with open(f"{input_dir}/Speck_48_72_Broken.thy", 'w') as f:
        f.write(content)
    print("Created Speck 48/72 Broken")


# Create SKINNY 64/128 Broken (6 Rounds)
if os.path.exists(f"{input_dir}/SKINNY_64_128.thy"):
    with open(f"{input_dir}/SKINNY_64_128.thy", 'r') as f:
        content = f.read()
    
    # 1. Change Theory Name
    content = content.replace("theory SKINNY_64_128", "theory SKINNY_64_128_Broken")
    
    # 2. Change Round Constant (36 -> 6)
    # Drastic reduction for clear structural contrast
    content = content.replace('definition skinny_rounds :: nat where "skinny_rounds = 36"', 
                              'definition skinny_rounds :: nat where "skinny_rounds = 6"')
    
    with open(f"{input_dir}/SKINNY_64_128_Broken.thy", 'w') as f:
        f.write(content)
    
    print("Created SKINNY 64/128 Broken (6 Rounds)")

# 11. SPARX 64/128 Broken (2 Steps = 6 Rounds)
if os.path.exists(f"{input_dir}/Sparx_64_128.thy"):
    with open(f"{input_dir}/Sparx_64_128.thy", 'r') as f:
        content = f.read()
    content = content.replace('sparx_n_steps = 8', 'sparx_n_steps = 2')
    content = content.replace("theory Sparx_64_128", "theory Sparx_64_128_Broken")
    with open(f"{input_dir}/Sparx_64_128_Broken.thy", 'w') as f:
        f.write(content)
    print("Created SPARX Broken")


# 14. SPARX 64/128 Low (4 Steps = 12 Rounds)
# Attacks break ~15 rounds. 12 rounds is weak/low.
if os.path.exists(f"{input_dir}/Sparx_64_128.thy"):
    with open(f"{input_dir}/Sparx_64_128.thy", 'r') as f:
        content = f.read()
    content = content.replace('sparx_n_steps = 8', 'sparx_n_steps = 4')
    content = content.replace("theory Sparx_64_128", "theory Sparx_64_128_Low")
    with open(f"{input_dir}/Sparx_64_128_Low.thy", 'w') as f:
        f.write(content)
    print("Created SPARX Low")



# 13. RECTANGLE 64/80 Low (18 Rounds)
# Attacks break ~18 rounds. Setting rounds=18 gives 0 margin.
if os.path.exists(f"{input_dir}/rectangle_64_80.thy"):
    with open(f"{input_dir}/rectangle_64_80.thy", 'r') as f:
        content = f.read()
    content = content.replace('rectangle_rounds = 25', 'rectangle_rounds = 18')
    content = content.replace("theory rectangle_64_80", "theory rectangle_64_80_Low")
    with open(f"{input_dir}/rectangle_64_80_Low.thy", 'w') as f:
        f.write(content)
    print("Created RECTANGLE Low")


# 10. RECTANGLE 64/80 Broken (10 Rounds)
if os.path.exists(f"{input_dir}/rectangle_64_80.thy"):
    with open(f"{input_dir}/rectangle_64_80.thy", 'r') as f:
        content = f.read()
    content = content.replace('rectangle_rounds = 25', 'rectangle_rounds = 10')
    content = content.replace("theory rectangle_64_80", "theory rectangle_64_80_Broken")
    with open(f"{input_dir}/rectangle_64_80_Broken.thy", 'w') as f:
        f.write(content)
    print("Created RECTANGLE Broken")



# 9. GIFT 64/128 Broken (10 Rounds)
# Safer Replacement Logic
if os.path.exists(f"{input_dir}/gift_64_128.thy"):
    with open(f"{input_dir}/gift_64_128.thy", 'r') as f:
        content = f.read()
    
    # 1. Replace Theory Name
    content = content.replace("theory gift_64_128", "theory gift_64_128_Broken")
    
    # 2. Replace Rounds (Targeting just the number if unique, or the whole definition carefully)
    # Check if your file actually has exactly "gift_rounds = 28"
    if 'gift_rounds = 28' in content:
        content = content.replace('gift_rounds = 28', 'gift_rounds = 10')
    else:
        # Fallback if the definition line is complex
        import re
        content = re.sub(r'gift_rounds\s*=\s*28', 'gift_rounds = 10', content)

    with open(f"{input_dir}/gift_64_128_Broken.thy", 'w') as f:
        f.write(content)
    print("Created GIFT Broken")
    


# 12. GIFT 64/128 Low (19 Rounds)
# Attacks break ~20 rounds. 19 rounds is "Low/Borderline".
if os.path.exists(f"{input_dir}/gift_64_128.thy"):
    with open(f"{input_dir}/gift_64_128.thy", 'r') as f:
        content = f.read()
    
    # 1. Replace Theory Name
    content = content.replace("theory gift_64_128", "theory gift_64_128_Broken")
    
    # 2. Replace Rounds (Targeting just the number if unique, or the whole definition carefully)
    # Check if your file actually has exactly "gift_rounds = 28"
    if 'gift_rounds = 28' in content:
        content = content.replace('gift_rounds = 28', 'gift_rounds = 19')
    else:
        # Fallback if the definition line is complex
        import re
        content = re.sub(r'gift_rounds\s*=\s*28', 'gift_rounds = 19', content)

    with open(f"{input_dir}/gift_64_128_Low.thy", 'w') as f:
        f.write(content)
    print("Created GIFT Broken")



