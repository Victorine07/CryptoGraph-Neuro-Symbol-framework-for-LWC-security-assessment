theory Sparx_64_128_Broken
  imports
    "HOL-Library.Word"
    "HOL.Bit_Operations"
begin


definition sparx_block_size :: nat where "sparx_block_size = 64"


definition sparx_key_size :: nat where "sparx_key_size = 128"


definition sparx_n_steps :: nat where "sparx_n_steps = 2"


definition sparx_rounds_per_step :: nat where "sparx_rounds_per_step = 3"


definition sparx_word_size :: nat where "sparx_word_size = 16"


definition sparx_n_branches :: nat where "sparx_n_branches = 2"


definition sparx_n_words :: nat where "sparx_n_words = 4"


definition sparx_total_rounds :: nat where 
  "sparx_total_rounds = 8 * 3"


definition sparx_round_key_words :: nat where
  "sparx_round_key_words = 2"



definition sparx_rol :: "'a::len word \<Rightarrow> nat \<Rightarrow> 'a word" where
  "sparx_rol x r = word_rotl r x"


definition sparx_ror :: "'a::len word \<Rightarrow> nat \<Rightarrow> 'a word" where
  "sparx_ror x r = word_rotr r x"


definition sparx_A_perm_16 :: "16 word \<Rightarrow> 16 word \<Rightarrow> (16 word \<times> 16 word)" where
  "sparx_A_perm_16 x y = (
    let x_rot = sparx_ror x 7;
        x_new = x_rot + y;
        y_rot = sparx_rol y 2;
        y_new = xor y_rot x_new
    in (x_new, y_new))"


definition sparx_A_perm_16_inv :: "16 word \<Rightarrow> 16 word \<Rightarrow> (16 word \<times> 16 word)" where
  "sparx_A_perm_16_inv x y = (
    let y_temp = xor y x;
        y_new = sparx_ror y_temp 2;
        x_temp = x - y_new;
        x_new = sparx_rol x_temp 7
    in (x_new, y_new))"


definition sparx_L_w :: "16 word \<Rightarrow> 16 word" where
  "sparx_L_w x = xor (push_bit 8 x) (drop_bit 8 x)"

definition sparx_linear_layer :: "16 word list \<Rightarrow> 16 word list" where
"sparx_linear_layer s = (
  if length s = 4 then
    let
      t = sparx_L_w (xor (s ! 0) (s ! 1))
    in
      [ xor (s ! 2) t, xor (s ! 3) t,
        s ! 0, s ! 1 ]
  else s)"


definition sparx_linear_layer_inv :: "16 word list \<Rightarrow> 16 word list" where
  "sparx_linear_layer_inv s = (
    if length s = 4 then
      let t = sparx_L_w (xor (s ! 2) (s ! 3))
      in [s ! 2, s ! 3, xor (s ! 0) t, xor (s ! 1) t]
    else s)"


definition sparx_extract_key_words :: "128 word \<Rightarrow> 16 word list" where
  "sparx_extract_key_words master_key = 
    [ucast master_key,
     ucast (drop_bit 16 master_key),
     ucast (drop_bit 32 master_key),
     ucast (drop_bit 48 master_key),
     ucast (drop_bit 64 master_key),
     ucast (drop_bit 80 master_key),
     ucast (drop_bit 96 master_key),
     ucast (drop_bit 112 master_key)]"


function sparx_gen_key_schedule_iterate :: 
  "16 word list \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> 16 word list \<Rightarrow> 16 word list" where
  "sparx_gen_key_schedule_iterate k c idx rk = (
    if idx \<ge> sparx_total_rounds then rk
    else
      let rk_new = rk @ [k ! 0, k ! 1];
          (k0_new, k1_new) = sparx_A_perm_16 (k ! 0) (k ! 1);
          k2_new = (k ! 2) + k0_new;
          k3_new = (k ! 3) + k1_new + (word_of_nat c);
          k_rotated = [k ! 2, k ! 3, k ! 4, k ! 5, k ! 6, k ! 7, k ! 0, k ! 1];
          k_updated = [k0_new, k1_new, k2_new, k3_new] @ drop 4 k_rotated
      in sparx_gen_key_schedule_iterate k_updated (c + 1) (idx + 1) rk_new)"
  by pat_completeness auto
termination
  apply (relation "measure (\<lambda>(k, c, idx, rk). sparx_total_rounds - idx)")
  apply auto
  done


definition sparx_generate_key_schedule :: "128 word \<Rightarrow> 16 word list" where
  "sparx_generate_key_schedule master_key = (
    let key_words = 128 div 16;
        total_needed = (sparx_total_rounds + 1) * 2;
        initial_k = sparx_extract_key_words master_key
    in sparx_gen_key_schedule_iterate initial_k 1 0 [])"


function sparx_get_round_key_iterate ::
  "16 word list \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> 16 word list \<Rightarrow> 16 word list" where
  "sparx_get_round_key_iterate rk_words idx max_idx keys = (
    if idx \<ge> max_idx then keys
    else
      let base = idx * sparx_round_key_words;
          k1 = if base < length rk_words then rk_words ! base else 0;
          k2 = if base + 1 < length rk_words then rk_words ! (base + 1) else 0;
          keys_new = keys @ [k1, k2]
      in sparx_get_round_key_iterate rk_words (idx + 1) max_idx keys_new)"
   by pat_completeness auto
termination
  apply (relation "measure(\<lambda>(rk_words, idx, max_idx, keys). max_idx - idx)")
  apply auto
  done



definition sparx_get_all_round_keys :: "16 word list \<Rightarrow> 16 word list" where
"sparx_get_all_round_keys rk_words =
  sparx_get_round_key_iterate
    rk_words
    0
    sparx_total_rounds
    []"



definition sparx_whitening_index :: nat where
  "sparx_whitening_index =
     (sparx_total_rounds - 1) * sparx_round_key_words"


definition sparx_apply_encrypt_round :: 
  "16 word list \<Rightarrow> 16 word \<Rightarrow> 16 word \<Rightarrow> 16 word list" where
  "sparx_apply_encrypt_round state key1 key2 = (
    if length state = 4 then
      let s0_xor = xor (state ! 0) key1;
          (s0_new, s1_new) = sparx_A_perm_16 s0_xor (state ! 1);
          s2_xor = xor (state ! 2) key2;
          (s2_new, s3_new) = sparx_A_perm_16 s2_xor (state ! 3)
      in [s0_new, s1_new, s2_new, s3_new]
    else state)"


definition sparx_apply_decrypt_round :: 
  "16 word list \<Rightarrow> 16 word \<Rightarrow> 16 word \<Rightarrow> 16 word list" where
  "sparx_apply_decrypt_round state key1 key2 = (
    if length state = 4 then
      let (s2_new, s3_new) = sparx_A_perm_16_inv (state ! 2) (state ! 3);
          s2_final = xor s2_new key2;
          (s0_new, s1_new) = sparx_A_perm_16_inv (state ! 0) (state ! 1);
          s0_final = xor s0_new key1
      in [s0_final, s1_new, s2_final, s3_new]
    else state)"


function sparx_encrypt_step_iterate :: 
  "16 word list \<Rightarrow> 16 word list \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> 16 word list" where
  "sparx_encrypt_step_iterate state all_keys round step = (
    if round \<ge> 3 then state
    else
      let idx = step * 3 + round;
          key1 = if idx * 2 < length all_keys then all_keys ! (idx * 2) else 0;
          key2 = if idx * 2 + 1 < length all_keys then all_keys ! (idx * 2 + 1) else 0;
          new_state = sparx_apply_encrypt_round state key1 key2
      in sparx_encrypt_step_iterate new_state all_keys (round + 1) step)"
  by pat_completeness auto
termination
  apply (relation "measure (\<lambda>(state, all_keys, round, step). 3 - round)")
  apply auto
  done



function sparx_decrypt_step_iterate :: 
  "16 word list \<Rightarrow> 16 word list \<Rightarrow> nat \<Rightarrow> nat \<Rightarrow> 16 word list" where
  "sparx_decrypt_step_iterate state all_keys round step = (
    if round \<ge> 3 then state
    else
      let idx = step * 3 + (3 - round - 1);
          key1 = if idx * 2 < length all_keys then all_keys ! (idx * 2) else 0;
          key2 = if idx * 2 + 1 < length all_keys then all_keys ! (idx * 2 + 1) else 0;
          new_state = sparx_apply_decrypt_round state key1 key2
      in sparx_decrypt_step_iterate new_state all_keys (round + 1) step)"
  by pat_completeness auto
termination
  apply (relation "measure (\<lambda>(state, all_keys, round, step). 3 - round)")
  apply auto
  done


definition sparx_block_to_words :: "64 word \<Rightarrow> 16 word list" where
  "sparx_block_to_words block = 
    [ucast block,
     ucast (drop_bit 16 block),
     ucast (drop_bit 32 block),
     ucast (drop_bit 48 block)]"


definition sparx_words_to_block :: "16 word list \<Rightarrow> 64 word" where
  "sparx_words_to_block words = (
    if length words = 4 then
      foldl (\<lambda>acc i. 
        let idx = 4 - i - 1;
            shift = 16 * idx;
            word_val = if idx < length words then ucast (words ! idx) else 0
        in or (push_bit shift word_val) acc) 0 [0..<4]
    else 0)"


function sparx_decrypt_steps_iterate ::
  "16 word list \<Rightarrow> 16 word list \<Rightarrow> nat \<Rightarrow> 16 word list" where
"sparx_decrypt_steps_iterate state all_keys step = (
  if step \<ge> 8 then state
  else
    let rev_step = 8 - step - 1;
        state_after_rounds =
          sparx_decrypt_step_iterate
            state
            all_keys
            0
            rev_step;
        state_after_linear =
          if rev_step > 0 then
            sparx_linear_layer_inv state_after_rounds
          else state_after_rounds
    in sparx_decrypt_steps_iterate
         state_after_linear
         all_keys
         (step + 1))"
by pat_completeness auto
termination
  apply (relation "measure (\<lambda>(s, k, i). 8 - i)")
  apply auto
  done



function sparx_encrypt_steps_iterate :: 
  "16 word list \<Rightarrow> 16 word list \<Rightarrow> nat \<Rightarrow> 16 word list" where
  "sparx_encrypt_steps_iterate state all_keys step = (
    if step \<ge> 8 then state
    else
      let state_after_rounds = sparx_encrypt_step_iterate state all_keys 0 step;
          state_after_linear = if step < 8 - 1 then
              sparx_linear_layer state_after_rounds
            else state_after_rounds
      in sparx_encrypt_steps_iterate state_after_linear all_keys (step + 1))"
  by pat_completeness auto
termination
  apply (relation "measure (\<lambda>(state, all_keys, step). 8 - step)")
  apply auto
  done



definition sparx_encrypt_block ::
  "64 word \<Rightarrow> 16 word list \<Rightarrow> 64 word" where
"sparx_encrypt_block plaintext rk_words = (
  let state = sparx_block_to_words plaintext;
      all_keys = sparx_get_all_round_keys rk_words;
      wk_idx = sparx_whitening_index;
      wk1 = if wk_idx < length all_keys then all_keys ! wk_idx else 0;
      wk2 = if wk_idx + 1 < length all_keys then all_keys ! (wk_idx + 1) else 0;
      state_after_steps = sparx_encrypt_steps_iterate state all_keys 0;
      state_final =
        if length state_after_steps = 4 then
          [ xor (state_after_steps ! 0) wk1,
            state_after_steps ! 1,
            xor (state_after_steps ! 2) wk2,
            state_after_steps ! 3 ]
        else state_after_steps
  in sparx_words_to_block state_final)"



definition sparx_decrypt_block ::
  "64 word \<Rightarrow> 16 word list \<Rightarrow> 64 word" where
"sparx_decrypt_block ciphertext rk_words = (
  let state = sparx_block_to_words ciphertext;
      all_keys = sparx_get_all_round_keys rk_words;
      wk_idx = sparx_whitening_index;
      wk1 = if wk_idx < length all_keys then all_keys ! wk_idx else 0;
      wk2 = if wk_idx + 1 < length all_keys then all_keys ! (wk_idx + 1) else 0;
      state_unwhitened =
        if length state = 4 then
          [ xor (state ! 0) wk1,
            state ! 1,
            xor (state ! 2) wk2,
            state ! 3 ]
        else state;
      state_after_steps =
        sparx_decrypt_steps_iterate state_unwhitened all_keys 0
  in sparx_words_to_block state_after_steps)"



definition sparx_encrypt :: "64 word \<Rightarrow> 128 word \<Rightarrow> 64 word" where
  "sparx_encrypt plaintext master_key = (
    let rk_words = sparx_generate_key_schedule master_key
    in sparx_encrypt_block plaintext rk_words)"


definition sparx_decrypt :: "64 word \<Rightarrow> 128 word \<Rightarrow> 64 word" where
  "sparx_decrypt ciphertext master_key = (
    let rk_words = sparx_generate_key_schedule master_key
    in sparx_decrypt_block ciphertext rk_words)"

definition sparx_test_key :: "128 word" where
  "sparx_test_key = 0x0123456789ABCDEF0123456789ABCDEF"


definition sparx_test_plaintext :: "64 word" where
  "sparx_test_plaintext = 0xDEADBEEFCAFEBABE"


end