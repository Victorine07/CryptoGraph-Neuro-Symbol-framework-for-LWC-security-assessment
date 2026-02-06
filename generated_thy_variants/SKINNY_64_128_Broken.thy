theory SKINNY_64_128_Broken
  imports
    "HOL-Library.Word"
    "HOL.Bit_Operations"
begin

section ‹SKINNY 64-128: Full Core Definitions›

subsection ‹Configuration Constants›

definition skinny_rounds :: nat where "skinny_rounds = 6"

subsection ‹Cell Access Helper Functions›

definition skinny_get_cell :: "nat ⇒ 64 word ⇒ 4 word" where
  "skinny_get_cell i s = word_of_int ((uint s div 2^(4 * i)) mod 16)"

definition skinny_set_cell :: "nat ⇒ 4 word ⇒ 64 word ⇒ 64 word" where
  "skinny_set_cell i c s = (
    let shift_val = 4 * i;
        clear_mask = not (push_bit shift_val (0xF :: 64 word))
    in or (and s clear_mask) (push_bit shift_val (ucast c :: 64 word)))"

subsection ‹SubCells (SC) Layer and Inverse›

definition skinny_sbox_table :: "nat list" where 
  "skinny_sbox_table = [0xC, 0x6, 0x9, 0x0, 0x1, 0xA, 0x2, 0xB, 0x3, 0x8, 0x5, 0xD, 0x4, 0xE, 0x7, 0xF]"

definition skinny_sbox_inv_table :: "nat list" where 
  "skinny_sbox_inv_table = [0x3, 0x4, 0x6, 0x8, 0xC, 0xA, 0x1, 0xE, 0x9, 0x2, 0x5, 0x7, 0x0, 0xB, 0xD, 0xF]"

definition skinny_sub_cells :: "64 word ⇒ 64 word" where
  "skinny_sub_cells s =
    foldr (λi acc. skinny_set_cell i (of_nat (skinny_sbox_table ! unat (skinny_get_cell i acc))) acc) [0..<16] s"

definition skinny_sub_cells_inv :: "64 word ⇒ 64 word" where
  "skinny_sub_cells_inv s =
    foldr (λi acc. skinny_set_cell i (of_nat (skinny_sbox_inv_table ! unat (skinny_get_cell i acc))) acc) [0..<16] s"

subsection ‹Add Round Constant (ARC)›

definition skinny_rc_table :: "6 word list" where
  "skinny_rc_table = map of_nat [0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F, 0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B, 0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E, 0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D]"

definition skinny_add_round_constant :: "nat ⇒ 64 word ⇒ 64 word" where
"skinny_add_round_constant r s = (
    let rc = skinny_rc_table ! r;
        c0 = and rc 0xF;
        c1 = ucast (drop_bit 4 rc) :: 4 word;
        c2 = 0x2 :: 4 word
    in skinny_set_cell 0 (xor (skinny_get_cell 0 s) (ucast c0))
       (skinny_set_cell 4 (xor (skinny_get_cell 4 s) c1)
       (skinny_set_cell 8 (xor (skinny_get_cell 8 s) c2) s)))"

subsection ‹ShiftRows (SR) Layer and Inverse›

definition skinny_sr_map :: "nat list" where 
  "skinny_sr_map = [0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14]"

definition skinny_sr_inv_map :: "nat list" where 
  "skinny_sr_inv_map = [0, 1, 2, 3, 7, 4, 5, 6, 10, 11, 8, 9, 13, 14, 15, 12]"

definition skinny_shift_rows :: "64 word ⇒ 64 word" where
  "skinny_shift_rows s =
    foldr (λi acc. skinny_set_cell i (skinny_get_cell (skinny_sr_map ! i) s) acc) [0..<16] 0"

definition skinny_shift_rows_inv :: "64 word ⇒ 64 word" where
  "skinny_shift_rows_inv s =
    foldr (λi acc. skinny_set_cell i (skinny_get_cell (skinny_sr_inv_map ! i) s) acc) [0..<16] 0"

subsection ‹MixColumns (MC) Layer and Inverse›

definition skinny_mc_transform :: "4 word list ⇒ 4 word list" where
"skinny_mc_transform cs = [xor (xor (cs!0) (cs!2)) (cs!3), cs!0, xor (cs!1) (cs!2), xor (cs!0) (cs!2)]"

definition skinny_mc_inv_transform :: "4 word list ⇒ 4 word list" where
"skinny_mc_inv_transform cs = [cs!1, xor (xor (xor (cs!0) (cs!1)) (cs!2)) (cs!3), xor (xor (cs!0) (cs!2)) (cs!3), xor (cs!0) (cs!1)]"

definition skinny_mix_columns :: "64 word ⇒ 64 word" where
"skinny_mix_columns s = (
  let col = λj. [skinny_get_cell j s, skinny_get_cell (j+4) s, skinny_get_cell (j+8) s, skinny_get_cell (j+12) s];
      c0 = skinny_mc_transform (col 0); c1 = skinny_mc_transform (col 1);
      c2 = skinny_mc_transform (col 2); c3 = skinny_mc_transform (col 3);
      res = [c0!0, c1!0, c2!0, c3!0, c0!1, c1!1, c2!1, c3!1, c0!2, c1!2, c2!2, c3!2, c0!3, c1!3, c2!3, c3!3]
  in foldr (λ(i,cv) acc. skinny_set_cell i cv acc) (zip [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15] res) 0)"

definition skinny_mix_columns_inv :: "64 word ⇒ 64 word" where
"skinny_mix_columns_inv s = (
  let col = λj. [skinny_get_cell j s, skinny_get_cell (j+4) s, skinny_get_cell (j+8) s, skinny_get_cell (j+12) s];
      c0 = skinny_mc_inv_transform (col 0); c1 = skinny_mc_inv_transform (col 1);
      c2 = skinny_mc_inv_transform (col 2); c3 = skinny_mc_inv_transform (col 3);
      res = [c0!0, c1!0, c2!0, c3!0, c0!1, c1!1, c2!1, c3!1, c0!2, c1!2, c2!2, c3!2, c0!3, c1!3, c2!3, c3!3]
  in foldr (λ(i,cv) acc. skinny_set_cell i cv acc) (zip [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15] res) 0)"

subsection ‹Tweakey Schedule (TK2 LFSR)›

definition skinny_lfsr2 :: "4 word ⇒ 4 word" where
"skinny_lfsr2 c = (
  let b3 = bit c 3; b2 = bit c 2;
      nb = (if (b3 ≠ b2) then (1 :: 4 word) else 0)
  in or (push_bit 1 (and c 0x7)) nb)"

definition skinny_tk_update :: "bool ⇒ 64 word ⇒ 64 word" where
"skinny_tk_update apply_lfsr tk = (
  let c = λj. skinny_get_cell j tk;
      p = [c 9, c 15, c 8, c 13, c 10, c 14, c 12, c 11, c 0, c 1, c 2, c 3, c 4, c 5, c 6, c 7];
      res = (if apply_lfsr then map (λi. if i < 8 then p!i else skinny_lfsr2 (p!i)) [0..<16] else p)
  in foldr (λ(j,v) acc. skinny_set_cell j v acc) (zip [0..<16] res) 0)"

fun skinny_gen_keys :: "64 word ⇒ 64 word ⇒ nat ⇒ 64 word list" where
  "skinny_gen_keys tk1 tk2 0 = []"
| "skinny_gen_keys tk1 tk2 (Suc n) = 
    xor tk1 tk2 # skinny_gen_keys (skinny_tk_update False tk1) (skinny_tk_update True tk2) n"

subsection ‹Round Functions›

definition skinny_encrypt_round :: "64 word ⇒ nat ⇒ 64 word ⇒ 64 word" where
"skinny_encrypt_round k r s = 
  skinny_mix_columns (skinny_shift_rows (xor (skinny_add_round_constant r (skinny_sub_cells s)) k))"

definition skinny_decrypt_round_inv :: "64 word ⇒ nat ⇒ 64 word ⇒ 64 word" where
"skinny_decrypt_round_inv k r s = 
  skinny_sub_cells_inv (skinny_add_round_constant r (xor (skinny_shift_rows_inv (skinny_mix_columns_inv s)) k))"

subsection ‹Iteration Logic›

fun skinny_encrypt_iterate :: "64 word ⇒ 64 word list ⇒ nat ⇒ 64 word" where
  "skinny_encrypt_iterate s [] _ = s"
| "skinny_encrypt_iterate s (k#ks) r = skinny_encrypt_iterate (skinny_encrypt_round k r s) ks (r + 1)"

fun skinny_decrypt_iterate :: "64 word ⇒ 64 word list ⇒ nat ⇒ 64 word" where
  "skinny_decrypt_iterate s ks r = foldl (λacc (k, round). skinny_decrypt_round_inv k round acc) s (rev (zip ks [0..<36]))"

end