theory HIGHT_64_128_Broken
  imports
    "HOL-Library.Word"
    "HOL.Bit_Operations"
    "HOL.List"
begin

section \<open>HIGHT 64-128: Full Core Definitions\<close>

subsection \<open>Configuration Constants\<close>

definition hight_rounds :: nat where "hight_rounds = 12"

subsection \<open>Delta Constants (Key Schedule)\<close>

definition hight_delta :: "8 word list" where
  "hight_delta = [
    0x5a, 0x6d, 0x36, 0x1b, 0x0d, 0x06, 0x03, 0x41, 0x60, 0x30, 0x18, 0x4c, 0x66, 0x33, 0x59, 0x2c,
    0x16, 0x0b, 0x45, 0x62, 0x31, 0x58, 0x2c, 0x16, 0x0b, 0x45, 0x62, 0x31, 0x58, 0x6c, 0x36, 0x1b,
    0x4d, 0x66, 0x73, 0x79, 0x7c, 0x3e, 0x1f, 0x4f, 0x67, 0x73, 0x79, 0x7c, 0x3e, 0x1f, 0x4f, 0x67,
    0x33, 0x19, 0x0c, 0x06, 0x43, 0x21, 0x10, 0x08, 0x44, 0x22, 0x11, 0x48, 0x24, 0x12, 0x09, 0x04,
    0x42, 0x61, 0x70, 0x38, 0x1c, 0x0e, 0x07, 0x43, 0x21, 0x10, 0x48, 0x24, 0x52, 0x69, 0x34, 0x1a,
    0x0d, 0x46, 0x63, 0x71, 0x78, 0x3c, 0x1e, 0x0f, 0x47, 0x63, 0x71, 0x78, 0x3c, 0x1e, 0x0f, 0x47,
    0x23, 0x51, 0x68, 0x74, 0x3a, 0x1d, 0x4e, 0x67, 0x33, 0x59, 0x6c, 0x76, 0x3b, 0x5d, 0x6e, 0x37,
    0x5b, 0x6d, 0x76, 0x7b, 0x3d, 0x5e, 0x6f, 0x77, 0x7b, 0x3d, 0x5e, 0x6f, 0x77, 0x3b, 0x5d, 0x6e]"

subsection \<open>Core Round Components\<close>

definition hight_F0 :: "8 word \<Rightarrow> 8 word" where
  "hight_F0 x = xor (xor (word_rotl 1 x) (word_rotl 2 x)) (word_rotl 7 x)"

definition hight_F1 :: "8 word \<Rightarrow> 8 word" where
  "hight_F1 x = xor (xor (word_rotl 3 x) (word_rotl 4 x)) (word_rotl 6 x)"

subsection \<open>Key Schedule Generation\<close>

definition hight_whitening_keys :: "8 word list \<Rightarrow> 8 word list" where
  "hight_whitening_keys MK = [
    MK!12, MK!13, MK!14, MK!15, MK!0, MK!1, MK!2, MK!3]"

function hight_subkeys_rec :: "nat \<Rightarrow> 8 word list \<Rightarrow> 8 word list list" where
  "hight_subkeys_rec i MK = (
    if i \<ge> 8 then []
    else
      let sk = map (\<lambda>j. (MK ! (((j - i) mod 8) + (if j < 8 then 0 else 8))) + (hight_delta ! (16 * i + j))) [0..<16]
      in sk # hight_subkeys_rec (i + 1) MK)"
  by pat_completeness auto
termination by (relation "measure (\<lambda>(i, MK). 8 - i)") auto

definition hight_gen_subkeys :: "8 word list \<Rightarrow> 8 word list" where
  "hight_gen_subkeys MK = concat (hight_subkeys_rec 0 MK)"

subsection \<open>Initial and Final Transformations\<close>

definition hight_initial_trans :: "8 word list \<Rightarrow> 8 word list \<Rightarrow> 8 word list" where
  "hight_initial_trans P WK = [
    (P ! 0) + (WK ! 0), P ! 1, xor (P ! 2) (WK ! 1), P ! 3,
    (P ! 4) + (WK ! 2), P ! 5, xor (P ! 6) (WK ! 3), P ! 7]"

definition hight_initial_trans_inv :: "8 word list \<Rightarrow> 8 word list \<Rightarrow> 8 word list" where
  "hight_initial_trans_inv C WK = [
    (C ! 0) - (WK ! 0), C ! 1, xor (C ! 2) (WK ! 1), C ! 3,
    (C ! 4) - (WK ! 2), C ! 5, xor (C ! 6) (WK ! 3), C ! 7]"

definition hight_final_trans :: "8 word list \<Rightarrow> 8 word list \<Rightarrow> 8 word list" where
  "hight_final_trans X WK = [
    (X ! 1) + (WK ! 4), X ! 2, xor (X ! 3) (WK ! 5), X ! 4,
    (X ! 5) + (WK ! 6), X ! 6, xor (X ! 7) (WK ! 7), X ! 0]"

definition hight_final_trans_inv :: "8 word list \<Rightarrow> 8 word list \<Rightarrow> 8 word list" where
  "hight_final_trans_inv Y WK = [
    Y ! 7, (Y ! 0) - (WK ! 4), Y ! 1, xor (Y ! 2) (WK ! 5),
    Y ! 3, (Y ! 4) - (WK ! 6), Y ! 5, xor (Y ! 6) (WK ! 7)]"

subsection \<open>Round Logic and Iteration\<close>

definition hight_enc_round :: "nat \<Rightarrow> 8 word list \<Rightarrow> 8 word list \<Rightarrow> 8 word list" where
  "hight_enc_round i X SK = [
    xor (X ! 7) ((hight_F0 (X ! 6)) + (SK ! (4 * i + 3))),
    X ! 0,
    (X ! 1) + (xor (hight_F1 (X ! 0)) (SK ! (4 * i))),
    X ! 2,
    xor (X ! 3) ((hight_F0 (X ! 2)) + (SK ! (4 * i + 1))),
    X ! 4,
    (X ! 5) + (xor (hight_F1 (X ! 4)) (SK ! (4 * i + 2))),
    X ! 6]"

definition hight_dec_round_inv :: "nat \<Rightarrow> 8 word list \<Rightarrow> 8 word list \<Rightarrow> 8 word list" where
  "hight_dec_round_inv i X SK = [
    X ! 1,
    (X ! 2) - (xor (hight_F1 (X ! 1)) (SK ! (4 * i))),
    X ! 3,
    xor (X ! 4) ((hight_F0 (X ! 3)) + (SK ! (4 * i + 1))),
    X ! 5,
    (X ! 6) - (xor (hight_F1 (X ! 5)) (SK ! (4 * i + 2))),
    X ! 7,
    xor (X ! 0) ((hight_F0 (X ! 7)) + (SK ! (4 * i + 3)))]"

function hight_encrypt_iterate :: "8 word list \<Rightarrow> 8 word list \<Rightarrow> 8 word list \<Rightarrow> nat \<Rightarrow> 8 word list" where
  "hight_encrypt_iterate X WK SK i = (
    if i \<ge> 12 then hight_final_trans X WK
    else hight_encrypt_iterate (hight_enc_round i X SK) WK SK (i + 1))"
  by pat_completeness auto
termination by (relation "measure (\<lambda>(X, WK, SK, i). 12 - i)") auto

function hight_decrypt_iterate :: "8 word list \<Rightarrow> 8 word list \<Rightarrow> 8 word list \<Rightarrow> nat \<Rightarrow> 8 word list" where
  "hight_decrypt_iterate X WK SK i = (
    if i \<ge> 12 then hight_initial_trans_inv X WK
    else 
      let round_idx = (12 - 1) - i in
      hight_decrypt_iterate (hight_dec_round_inv round_idx X SK) WK SK (i + 1))"
  by pat_completeness auto
termination by (relation "measure (\<lambda>(X, WK, SK, i). 12 - i)") auto

end