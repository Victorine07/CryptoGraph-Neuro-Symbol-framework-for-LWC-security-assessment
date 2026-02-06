theory Simeck_48_96
  imports
    "HOL-Library.Word"
    "HOL.Bit_Operations"
begin


fun simeck_get_sequence_rec :: "nat \<Rightarrow> nat \<Rightarrow> bool list \<Rightarrow> bool list" where
  "simeck_get_sequence_rec 0 idx states = states"
| "simeck_get_sequence_rec (Suc n) idx states = (
    let feedback = (states ! idx) \<noteq> (states ! (idx + 2))
    in simeck_get_sequence_rec n (idx + 1) (states @ [feedback]))"


definition simeck_round_constants_sequence :: "bool list" where
  "simeck_round_constants_sequence = simeck_get_sequence_rec (36 - 5) 0 (replicate 5 True)"


definition simeck_F_function :: "24 word \<Rightarrow> 24 word" where
  "simeck_F_function x = xor (and x (word_rotl 5 x)) (word_rotl 1 x)"


definition simeck_encrypt_round :: "24 word \<Rightarrow> 24 word \<times> 24 word \<Rightarrow> 24 word \<times> 24 word" where
  "simeck_encrypt_round k xy = (
    let (left, right) = xy in 
    (xor (xor (simeck_F_function left) right) k, left))"


definition simeck_decrypt_round_inverse :: "24 word \<Rightarrow> 24 word \<times> 24 word \<Rightarrow> 24 word \<times> 24 word" where
  "simeck_decrypt_round_inverse k xy_new = (
    let (left_new, right_new) = xy_new in 
    (right_new, xor (xor left_new k) (simeck_F_function right_new)))"


definition simeck_key_schedule_constant :: "24 word" where
  "simeck_key_schedule_constant = 0xFFFFFC"


fun simeck_gen_key_schedule_rec :: "24 word list \<Rightarrow> bool list \<Rightarrow> 24 word list" where
  "simeck_gen_key_schedule_rec states [] = []"
| "simeck_gen_key_schedule_rec states (c#cs) = (
    let k_0 = states ! 0;
        left = states ! 1;
        right = states ! 0;
        round_const = xor simeck_key_schedule_constant (if c then 1 else 0);
        (new_left, new_right) = simeck_encrypt_round round_const (left, right);
        new_states = (tl states) @ [new_left]
    in k_0 # simeck_gen_key_schedule_rec (new_states[0 := new_right]) cs)"


definition simeck_generate_key_schedule :: "24 word list \<Rightarrow> 24 word list" where
  "simeck_generate_key_schedule initial_keys = 
     simeck_gen_key_schedule_rec initial_keys simeck_round_constants_sequence"



fun simeck_encrypt_iterate :: "24 word \<times> 24 word \<Rightarrow> 24 word list \<Rightarrow> 24 word \<times> 24 word" where
  "simeck_encrypt_iterate state [] = state"
| "simeck_encrypt_iterate state (k#ks) = simeck_encrypt_iterate (simeck_encrypt_round k state) ks"


fun simeck_decrypt_iterate :: "24 word \<times> 24 word \<Rightarrow> 24 word list \<Rightarrow> 24 word \<times> 24 word" where
  "simeck_decrypt_iterate state ks = foldl (\<lambda>st_new k. simeck_decrypt_round_inverse k st_new) state (rev ks)"



definition simeck_encrypt_block :: "24 word \<times> 24 word \<Rightarrow> 24 word list \<Rightarrow> 24 word \<times> 24 word" where
  "simeck_encrypt_block plaintext keys = simeck_encrypt_iterate plaintext keys"


definition simeck_decrypt_block :: "24 word \<times> 24 word \<Rightarrow> 24 word list \<Rightarrow> 24 word \<times> 24 word" where
  "simeck_decrypt_block ciphertext keys = simeck_decrypt_iterate ciphertext keys"


definition simeck_encrypt :: "48 word \<Rightarrow> 24 word list \<Rightarrow> 48 word" where
  "simeck_encrypt plaintext keys = (
    let left = ucast (drop_bit 24 plaintext);
        right = ucast plaintext;
        (c_left, c_right) = simeck_encrypt_block (left, right) keys
    in or (push_bit 24 (ucast c_left)) (ucast c_right))"


definition simeck_decrypt :: "48 word \<Rightarrow> 24 word list \<Rightarrow> 48 word" where
  "simeck_decrypt ciphertext keys = (
    let left = ucast (drop_bit 24 ciphertext);
        right = ucast ciphertext;
        (p_left, p_right) = simeck_decrypt_block (left, right) keys
    in or (push_bit 24 (ucast p_left)) (ucast p_right))"


end