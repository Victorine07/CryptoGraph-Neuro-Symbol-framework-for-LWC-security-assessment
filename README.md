# CryptoGraph-Neuro-Symbolic-framework-for-LWC-security-assessment

** A Formal Verification-Driven Framework for Automated Cryptanalysis**

This repository contains the official implementation of the framework CryptoGraph: A Neuro-Symbolic Automated Framework For Lightweight Block Ciphers Security Evaluation

We introduce a novel methodology that bridges **Formal Methods** and **Geometric Deep Learning**. By translating formal cryptographic specifications (Isabelle/HOL) into semantic Abstract Syntax Trees (ASTs), we train a **Hybrid Graph Attention Network (HybridGAT)** to predict the security of lightweight ciphers. Unlike traditional statistical tools, this model learns to reason about cryptographic structure, achieving **Zero-Shot Generalization** on unseen cipher architectures.

## Supported Primitives
This framework covers the three dominant block ciphers in lightweight cryptography.

| Family | Ciphers Included | Role in Study |
| :--- | :--- | :--- |
| **Feistel** | **Simon**, **Simeck**, **Xtea** | Training / Validation |
| **SPN** | **PRESENT**, **GIFT**, **SKINNY**, **RECTANGLE** | Training / **Zero-Shot Testing** (Unseen) |
| **ARX** | **HIGHT**, **Speck**, **Sparx** (Hybrid) | Training / **Zero-Shot Testing** (Unseen) |

##  Project Workflow

The pipeline is modularized into four sequential steps, bridging the gap between Isabelle theory files and Graph Neural Networks.

### 1. Formal Specification & Variant Generation
* **Notebook:** `STEP-1-thy_variants_generation.ipynb`
* **Description:** Generates strictly typed Isabelle/HOL theory files (`.thy`) for cipher variants.
* **Process:** Uses a "Stateless Refactoring" protocol to translate imperative reference code (Python) into pure functional logic, creating mathematically verifiable specifications for varying key sizes, block sizes, and rounds.

### 2. Neuro-Symbolic Extraction (AST + PDV)
* **Notebook:** `STEP-2-thy2AST_json_generation-V2.ipynb`
* **Description:** Parses the Isabelle/HOL theories to extract the **Graph Topology** and **Parametric Features**.
* **Output:**
    * **AST (Abstract Syntax Tree):** Captures the dependency graph of cryptographic operations (Data Flow).
    * **PDV (Protocol Description Vector):** A high-dimensional vector capturing metadata (e.g., S-box nonlinearity, Diffusion/Confusion balance).

### 3. Structural Augmentation
* **Notebook:** `STEP-3-Augmentation_Strategies-V2.ipynb`
* **Description:** Applies semantic-preserving transformations to the ASTs to tackle data scarcity.
* **Techniques:** Variable Renaming, Operand Swapping (Commutativity), and Dead Code Injection to robustify the model against superficial syntax changes.

### 4. HybridGAT Training & Glass-Box Analysis
* **Notebook:** `STEP-4-Training_Hybrid_Model-GNN-MLP-V2.ipynb`
* **Description:** Trains the Neuro-Symbolic architecture.
* **Key Capabilities:**
    * **Hybrid Architecture:** Fuses GNN (Topological Reasoning) with MLP (Feature Analysis).
    * **Zero-Shot Inference:** Evaluates the model on **GIFT** and **SKINNY** (never seen during training).
    * **Glass-Box Interpretability:** Extracts attention weights to visualize which code regions (e.g., `SBOX_Layer` vs `Key_Schedule`) the model prioritizes.

### Key Results

* **94% F1-Score:** Outperforms XGBoost and Random Forest on structural security classification.
* **Zero-Shot Generalization:** Successfully identifies the security levels of **SKINNY-128** (High) and **GIFT** (High) without prior training on SPN architectures.
* **Paradigm Awareness:** The interpretability analysis proves the model dynamically shifts focus:
    * **Feistel:** Focuses on `ROTL` and `XOR` (Diffusion).
    * **ARX:** Focuses on `ADD` (Modular Addition) and `LIST_INDEX`.
    * **SPN:** Focuses on `SBOX_Layer` and `Permutation_Layer`.


## Core Dependencies
Requirements: Python 3.8+
pip install numpy pandas scikit-learn

### Graph Deep Learning (PyTorch Geometric)
pip install torch torch-geometric

#### Disclaimer
This project explores the intersection of AI and Cryptography. AI Assistance Declaration: Large Language Models (LLMs) were utilized in the development of this framework to:
- Assist in the syntactical translation of Python reference code to Isabelle/HOL.
- Refine the plotting code for interpretability visualization.
The security labels and formal verification logic remain grounded in established cryptographic literature and the Isabelle theorem prover.

