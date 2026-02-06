theory Simon_128_128
  imports
    "HOL-Library.Word"
    "HOL.Bit_Operations"
    "HOL.List"
begin


definition simon_z2 :: int where "simon_z2 = 0b11001101101001111110001000010100011001001011000000111011110101"


definition simon_F_function :: "64 word ⇒ 64 word" where
  "simon_F_function x = xor (and (word_rotl 1 x) (word_rotl 8 x)) (word_rotl 2 x)"


definition simon_encrypt_round :: "64 word ⇒ 64 word × 64 word ⇒ 64 word × 64 word" where
  "simon_encrypt_round k xy = (let (x, y) = xy in (xor (xor k (simon_F_function x)) y, x))"


definition simon_decrypt_round_inverse :: "64 word ⇒ 64 word × 64 word ⇒ 64 word × 64 word" where
  "simon_decrypt_round_inverse k xy_new = (let (x_new, y_new) = xy_new in (y_new, xor (xor x_new k) (simon_F_function y_new)))"



definition simon_rho_const :: "64 word" where
  "simon_rho_const = 0xFFFFFFFFFFFFFFFC"


function simon_gen_key_schedule_rec :: "64 word list ⇒ nat ⇒ 64 word list" where
  "simon_gen_key_schedule_rec ks i = (if i ≥ 68 then ks else
    let z_bit = bit 0b11001101101001111110001000010100011001001011000000111011110101 (i - 2);
        rs_3 = word_rotr 3 (ks ! (i-1)); rs_1 = word_rotr 1 rs_3;
        new_k = xor (xor (xor (ks ! (i-2)) rs_3) rs_1) (xor (if z_bit then 1 else 0) simon_rho_const)
    in simon_gen_key_schedule_rec (ks @ [new_k]) (i+1))"
  by pat_completeness auto
termination by (relation "measure (λ(ks, i). 68 - i)") auto


definition simon_generate_key_schedule :: "64 word list ⇒ 64 word list" where
  "simon_generate_key_schedule init = simon_gen_key_schedule_rec init (length init)"


fun simon_encrypt_iterate :: "64 word × 64 word ⇒ 64 word list ⇒ 64 word × 64 word" where
  "simon_encrypt_iterate st [] = st" | "simon_encrypt_iterate st (k#ks) = simon_encrypt_iterate (simon_encrypt_round k st) ks"


fun simon_decrypt_iterate :: "64 word × 64 word ⇒ 64 word list ⇒ 64 word × 64 word" where
  "simon_decrypt_iterate st ks = foldl (λst_new k. simon_decrypt_round_inverse k st_new) st (rev ks)"


definition simon_encrypt_block ::
  "64 word × 64 word ⇒ 64 word list ⇒ 64 word × 64 word" where
"simon_encrypt_block state keys =
   simon_encrypt_iterate state keys"


definition simon_decrypt_block ::
  "64 word × 64 word ⇒ 64 word list ⇒ 64 word × 64 word" where
"simon_decrypt_block state keys =
   simon_decrypt_iterate state keys"


definition simon_encrypt ::
  "128 word ⇒ 64 word list ⇒ 128 word" where
"simon_encrypt plaintext keys =
  (let left  = ucast (drop_bit 64 plaintext);
       right = ucast plaintext;
       (c_l, c_r) = simon_encrypt_block (left, right) keys
   in or (push_bit 64 (ucast c_l)) (ucast c_r))"


definition simon_decrypt ::
  "128 word ⇒ 64 word list ⇒ 128 word" where
"simon_decrypt ciphertext keys =
  (let left  = ucast (drop_bit 64 ciphertext);
       right = ucast ciphertext;
       (p_l, p_r) = simon_decrypt_block (left, right) keys
   in or (push_bit 64 (ucast p_l)) (ucast p_r))"


end