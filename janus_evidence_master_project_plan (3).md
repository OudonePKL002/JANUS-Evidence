# JANUS-Evidence: Master Project Plan & Engineering Specification

> **Project Title:** JANUS-Evidence: Evidence-Grounded Multi-Agent Vulnerability Localization, Root-Cause Analysis, and Exploit Validation for Smart Contracts  
> **Principal Investigator:** Oudone Phengkhamlar  
> **Advisor:** Prof. Kwang-Man Ko  
> **Affiliation:** Software Security Laboratory, Sangji University  
> **Target Conference:** ACM AsiaCCS  
> **Final Submission Deadline:** December 11, 2026 (AoE)  
> **Document Version:** 1.2.0 (Complete Engineering & Evaluation Specification)

---

## 1. Executive Summary & Research Philosophy

### 1.1 Foundational Thesis

$$
\textbf{"Reproduction is NOT Causation."}
$$

Modern automated Proof-of-Concept (PoC) exploit generators and large language model (LLM) security agents evaluate success almost exclusively through replayability: *“Did the synthesized exploit transaction succeed?”* However, complex decentralized finance (DeFi) exploits routinely combine multiple sub-optimal patterns, reentrancies, and collateral imbalances. An exploit replay can succeed even when attributing the incident to a co-existing, non-essential bug. Exploit reproduction alone cannot isolate which specific flaw strictly caused the financial loss.

### 1.2 Mission Objectives

1. **Evidence Grounding (Mitigating Hallucination & Unbacked Claims):** Transform unstructured LLM security narratives into verifiable, pointer-backed causal statements. Enforce an **Evidence Gate** with an iterative revision loop ($R=3$). If a claim cannot link directly to structural or on-chain execution evidence, it is marked `UNGROUNDED` for revision; if unresolved, the framework abstains and returns `INCONCLUSIVE`.
2. **Causal Intervention ($do$-calculus in Historical Sandboxes):** Rigorously evaluate causal claims via active programmatic and state interventions ($do(\text{cause}=\text{off})$) on historical blockchain forks, quantitatively measuring **Necessity** ($\ge 0.9$) and **Specificity** ($\ge 0.8$).
3. **Role-Specialized Decomposition:** Demonstrate that an orchestrated pipeline of four specialized agents (Auditor $\to$ Localization $\to$ RCA $\to$ Exploit) using an explicit Evidence Graph outperforms homogeneous single-agent baselines under equivalent inference budgets.

---

## 2. System Architecture & Formal Specification

```
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

### 2.1 The Evidence Graph Schema: $G = (N, E)$

Every agent claim must strictly resolve to explicit identifiers in the Evidence Graph:

* **Node Types ($N$):** `CodeNode`, `StateNode`, `TxNode`, `CallNode`, `AssetNode`, `InvariantNode`.
* **Edge Types ($E$):** `DEPENDS_ON`, `CALLS`, `MODIFIES_STATE`, `TRANSFERS_ASSET`, `VIOLATES`.

### 2.2 Formal Interventional Metrics

* **Metric 1: Necessity ($\text{Nec}$)**
  $$
  \text{Nec}(c) = 1 - \frac{\text{Profit}(\text{Fork}(b), do(c = \text{off}))}{\text{Profit}_{\text{orig}}}
  $$
  *Acceptance Threshold:* $\text{Nec}(c) \ge \tau_n = 0.9$

* **Metric 2: Specificity ($\text{Spec}$)**
  $$
  \text{Spec}(c) = \frac{1}{k} \sum_{i=1}^{k} \mathbb{I}\left( \text{Profit}(\text{Fork}(b), do(\text{ctrl}_i = \text{off})) \ge (1 - \epsilon) \cdot \text{Profit}_{\text{orig}} \right)
  $$
  *Acceptance Threshold:* $\text{Spec}(c) \ge \tau_s = 0.8$ ($k \ge 10$)

### 2.3 RCA Accuracy & 6-Slot Output Specification

To ensure rigorous evaluation, RCA output is not graded on general narrative quality, but on a strict **6-slot exact match** evaluated alongside expert annotators (Cohen’s $\kappa \ge 0.7$). The required slots are:
1. **Pre-attack State:** The protocol condition prior to exploitation.
2. **Attacker Input:** The specific malicious transaction payload/parameters.
3. **Vulnerable Operation:** The precise AST statement/function causing the flaw.
4. **State Invariant Breakdown:** The mathematical security invariant that was violated.
5. **Asset Flow Impact:** The resulting token drain or collateral manipulation.
6. **Minimal Causal Chain:** The sequential order of operations linking 1 through 5.

---

## 3. Benchmark Datasets & Baseline Matrix

### 3.1 Dataset Manifest

| Dataset | Scale | Purpose | Characteristics |
| :--- | :--- | :--- | :--- |
| **SmartBugs Curated / SolidiFI** | 143 contracts (sampled) | Baseline detection & localization | Synthetic/isolated single-contract bugs |
| **JANUS-EvidenceBench** | $\ge 100$ real-world incidents | Primary causal RCA & exploit validation | Multi-contract DeFi exploits replayed on historical forks |
| **Post-Cutoff Incidents** | $\ge 30$ incidents (2026 H2) | Temporal out-of-distribution evaluation | Controls for pre-training memorization & data contamination |

### 3.2 Comprehensive Baseline Configuration Matrix

| Group ID | Configuration | Evaluation Purpose / Focus |
| :--- | :--- | :--- |
| **B1. LLM-only** | Same LLM backbone + source/tx text; no external tools. | Raw reasoning baseline |
| **B2. Tool-using Single-Agent**| Same LLM & tools utilized via a ReAct single-agent. | Multi-agent role specialization impact |
| **B3. Reproduction-only** | Evaluates hypotheses solely via exploit success (TxRay/TracExp).| Causation vs. Reproduction (The Core Gap) |
| **B4. JANUS w/o Gate** | Evidence Graph active, but Evidence Gate pointer checks disabled. | Independent impact of Evidence Grounding |
| **B5. JANUS w/o Intervention**| Evidence Gate active, but causal $do()$-validation removed. | Independent impact of Validator |
| **B6. Evidence Ablation** | Controlled removal of Code, Trace, State, or Exploit layers. | Contribution weighting of specific evidence |
| **B7. Full JANUS-Evidence** | 4-Agent Pipeline + Evidence Gate + Interventional Validator. | Proposed Framework Maximum Performance |

---

## 4. Quantitative Target Standards (AsiaCCS Standard)

| Metric | Floor Target (Defensible) | Challenge Target | Benchmark / Comparison |
| :--- | :--- | :--- | :--- |
| **RCA Accuracy** | $\ge 75\%$ | $\ge 80\%$ | Exact 6-slot causal match |
| **FCER** | $\le 15\%$ | $\le 10\%$ | $\ge 40\%$ relative reduction vs. LLM-only |
| **Causal Classification F1** | $\ge 80\%$ | $\ge 85\%$ | $\ge +12\%p$ vs. reproduction-only |
| **Localization Top-1** | $\ge 75\%$ | $\ge 80\%$ | Vulnerable function/statement slice |
| **Analysis Coverage** | $\ge 85\%$ | $\ge 90\%$ | Validates low unnecessary abstention |
| **Post-Cutoff Drop** | $\le 10\%p$ | $\le 7\%p$ | OOD generalization capability |
| **Compute Cost/Incident** | $\le \$3.00$ | $\le \$2.00$ | Practical auditing constraint |

---

## 5. Master Schedule & Milestones (Deadline: Dec 11, 2026 AoE)

```
JANUS-Evidence Master Engineering Schedule
│
├── Phase 1: Environment, Dataset & System Prototyping
│   ├── [Complete: 2026-10-15] Task 1.1: Foundry Anvil harness & SoK Matrix
│   ├── [Deadline: 2026-10-28] Task 1.2: Evidence Graph Builder G=(N,E)
│   └── [Deadline: 2026-10-31] Task 1.3: 4-Agent Pipeline & Evidence Gate (R=3 Loop)
│
├── Phase 2: Experimental Execution & Ablation Studies
│   ├── [Deadline: 2026-11-10] Task 2.1: B4, B5, B6 Ablations (Gate, Layers, Validation)
│   ├── [Deadline: 2026-11-20] Task 2.2: B3 vs B7 (Intervention vs Reproduction)
│   └── [Deadline: 2026-11-25] Task 2.3: Post-Cutoff testing & Multi-Agent (B1, B2)
│
├── Phase 3: Paper Freezing & Open Science Artifact
│   ├── [Deadline: 2026-12-01] Task 3.1: 12-page ACM SIGCONF manuscript freeze
│   └── [Deadline: 2026-12-05] Task 3.2: Complete Open Science Artifact (Docker/Scripts)
│
└── Phase 4: Review, Proofing & Final Submission
    ├── [Deadline: 2026-12-08] Task 4.1: Internal review & English proofreading
    └── [Hard Deadline: 2026-12-11 AoE] Task 4.2: Final AsiaCCS 2027 paper submission
```

---

## 6. Experimental Threats to Validity & Mitigations

1. **Environment Mismatch & Replay Fidelity:**
   * *Threat:* Local historical forks may not perfectly simulate external state changes, resulting in false negatives during replay.
   * *Mitigation:* Explicitly log `environment mismatch` as a distinct failure class rather than a causal failure.
2. **MEV & Validator Collusion (Out of Scope):**
   * *Threat:* Exploits reliant on private mempools or block builder collusion cannot be reliably intervened upon in standard forks.
   * *Mitigation:* The threat model explicitly excludes privileged actor attacks. Analysis assumes public mempool and non-privileged attacker capabilities.
3. **Intervention Side-Effects (Control Stability):**
   * *Threat:* Applying $do(\text{cause}=\text{off})$ via AST modification might break compilation or alter unrelated control flows.
   * *Mitigation:* Validate Specificity using a high control size ($k \ge 10$) and size-matched non-causal mutations to ensure the $do()$-calculus isolated the exact causal variable without breaking general contract execution.