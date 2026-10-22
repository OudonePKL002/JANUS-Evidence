# JANUS-Evidence

> **Evidence-Grounded Multi-Agent Vulnerability Localization, Root-Cause Analysis, and Exploit Validation for Smart Contracts**  
> **Affiliation:** Software Security Laboratory, Sangji University  
> **Version:** 1.2.0

---

## 1. Problem Statement

$$
\textbf{"Reproduction is NOT Causation."}
$$

Modern automated Proof-of-Concept (PoC) exploit generators and large language model (LLM) security agents evaluate success almost exclusively through replayability: *"Did the synthesized exploit transaction succeed?"* However, complex decentralized finance (DeFi) exploits routinely combine multiple sub-optimal patterns, reentrancies, and collateral imbalances. An exploit replay can succeed even when attributing the incident to a co-existing, non-essential bug. Exploit reproduction alone cannot isolate which specific flaw strictly caused the financial loss.

**JANUS-Evidence** addresses this gap through three foundational pillars:
1. **Evidence Grounding:** Every agent claim must resolve to explicit node and edge pointers in the Evidence Graph $G = (N, E)$. An **Evidence Gate** enforces pointer validity with an iterative revision loop ($R = 3$), returning `INCONCLUSIVE` rather than hallucinating unbacked claims.
2. **Causal Intervention ($do$-calculus in Historical Sandboxes):** Validates root-cause claims via active programmatic and state interventions ($do(\text{cause}=\text{off})$) on historical blockchain forks, quantitatively measuring **Necessity** ($\tau_n = 0.9$) and **Specificity** ($\tau_s = 0.8$).
3. **Role-Specialized Multi-Agent Decomposition:** Orchestrates four specialized agents (`Auditor` $\to$ `Localizer` $\to$ `RCA` $\to$ `Exploit`) over a shared Evidence Graph, producing a strict **6-slot causal chain**.

---

## 2. System Architecture Overview

```text
[Target Contract Source/Bytecode & Historical Fork State]
                         │
                         ▼
   ┌─────────────────────────────────────────────────────────┐
   │ 1. Program & On-Chain Analyzer                          │
   │    - AST / CFG / DFG / Call Graph Extraction            │
   │    - Tx Trace / Storage State Diff / Token Flow Parsing │
   └──────────────────────────┬──────────────────────────────┘
                              │
                              ▼
   ┌─────────────────────────────────────────────────────────┐
   │ 2. Evidence Graph G = (N, E)                            │
   │    Nodes: Code, State, Tx, Call, Asset, Invariant       │
   └──────────────▲───────────────────────────▲──────────────┘
                  │ Read / Pointer Validation │
         ┌────────┴──────────────┐   ┌────────┴─────────────┐
         ▼                       ▼   ▼                      ▼
   ┌───────────┐           ┌───────────┐           ┌────────────────┐
   │  Auditor  │ ──(H)───> │Localizer  │ ──(L)───> │   RCA Agent    │
   │  Agent    │           │  Agent    │           │ (6-Slot Chain) │
   └───────────┘           └───────────┘           └───────┬────────┘
                                                           │
                                                           ▼
                                                   ┌────────────────┐
                                                   │ Evidence Gate  │◄────┐
                                                   │ (Pointer Check)│     │ Revise Loop
                                                   └───────┬────────┘     │ (Max R=3)
           (Max retries exceeded -> INCONCLUSIVE) ─────────┤(UNGROUNDED)──┘
                                                           │
                                      Pointers Validated   │
                                                           ▼
                                                   ┌────────────────┐
                                                   │ Exploit Agent  │
                                                   │ (Fork Replay)  │
                                                   └───────┬────────┘
                                          Replay Succeeded │
                                                           ▼
                                                   ┌────────────────────────────┐
                                                   │ Interventional Validator   │
                                                   │ do(cause=off) -> Necessity │
                                                   │ do(ctrl=off)  -> Specificity│
                                                   └────────────────────────────┘
```

### Evidence Graph Schema $G = (N, E)$
- **Nodes ($N$):** `CodeNode`, `StateNode`, `TxNode`, `CallNode`, `AssetNode`, `InvariantNode`
- **Edges ($E$):** `DEPENDS_ON`, `CALLS`, `MODIFIES_STATE`, `TRANSFERS_ASSET`, `VIOLATES`

---

## 3. Repository Structure

```text
janus-evidence/
├── benchmark/
│   ├── evidence_bench/ground_truth/  # >= 100 real-world DeFi incidents & 6-slot ground truth
│   ├── smartbugs_curated/            # 143 sampled single-contract baseline contracts
│   └── post_cutoff/                  # >= 30 post-cutoff (2026 H2) temporal OOD incidents
├── configs/                          # Model, threshold (tau_n=0.9, tau_s=0.8, R=3), & RPC configs
├── core/
│   ├── analyzer/                     # Evidence Graph G=(N,E) builder, static & trace parsers
│   ├── gate/                         # Evidence Gate pointer verification & R=3 revision loop
│   ├── agents/                       # Auditor, Localizer, RCA, and Exploit agents
│   └── validator/                    # Foundry Anvil sandbox & do-calculus Necessity/Specificity
├── experiments/                      # Baseline (B1-B7) & ablation evaluation runners
├── scripts/                          # Dataset preparation & replay utilities
└── tests/                            # Unit and integration tests
```

---

## 4. Initial Setup Instructions (Apple Silicon / ARM64)

### Option A: Local macOS Setup (`darwin/arm64`)
1. **Install Foundry (`anvil`, `forge`, `cast`):**
   ```bash
   curl -L https://foundry.paradigm.xyz | bash
   foundryup
   ```
2. **Create Virtual Environment & Install Dependencies:**
   ```bash
   make install
   source venv/bin/activate
   ```
3. **Verify Syntax & Run Test Suite:**
   ```bash
   make lint
   make test
   ```

### Option B: Docker Setup (`linux/arm64`)
```bash
make docker-build
docker run --rm -it janus-evidence:latest
```

