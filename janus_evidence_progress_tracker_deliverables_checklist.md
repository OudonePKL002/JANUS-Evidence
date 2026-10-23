# JANUS-Evidence: Project Progress Tracker & Deliverables Checklist

> **Project Title:** JANUS-Evidence: Evidence-Grounded Multi-Agent Vulnerability Localization, Root-Cause Analysis, and Exploit Validation for Smart Contracts  
> **Principal Investigator:** Oudone Phengkhamlar  
> **Advisor:** Prof. Kwang-Man Ko  
> **Affiliation:** Software Security Laboratory, Sangji University  
> **Target Venue:** ACM AsiaCCS  
> **Hard Deadline:** December 11, 2026 (AoE)  
> **Status Last Updated:** October 23, 2026  

---

## 📊 Overall Progress Summary

| Phase | Description | Timeline | Status | Completed Tasks |
| :---: | :--- | :---: | :---: | :---: |
| **Phase 1** | System Prototyping & Pipeline Bootstrap | Oct 5 – Oct 31, 2026 | **100% Complete** | 7 / 7 Tasks |
| **Phase 2** | Experiments, Ablations & Validation | Nov 1 – Nov 25, 2026 | **Ready to Start** | 0 / 5 Tasks |
| **Phase 3** | Manuscript Freezing & Artifact Packaging | Nov 26 – Dec 5, 2026 | **Pending** | 0 / 4 Tasks |
| **Phase 4** | Advisor Review, Proofing & Submission | Dec 6 – Dec 11, 2026 | **Pending** | 0 / 3 Tasks |

**Current Verification Status:** `23/23 Unit Tests Passing (100%)`  
**Git Working Branch:** `main`  
**Latest Git Hash (Phase 1):** Verified and tagged for Benchmark Loader.

---

## 🛠️ Phase 1: Environment, Dataset & System Prototyping (Oct 5 – Oct 31, 2026)
> **Goal:** Build the complete deterministic architecture, formal schemas, test suites, and benchmark infrastructure.

- [x] **Task 1.1: Project Directory Scaffold & Environment Files**
  - [x] Clean directory tree (`benchmark/`, `configs/`, `core/`, `experiments/`, `tests/`)
  - [x] Apple Silicon (ARM64) & Linux compatible `Dockerfile`
  - [x] Automation `Makefile` (`make install`, `make test`, `make lint`)
  - [x] Strict `.gitignore` (filtering out secrets, build caches, and RPC logs)
  - [x] Repository overview `README.md` and initial dependencies in `requirements.txt`
  - *Commit:* `87692de` (`chore(setup): initialize repository structure, Docker environment...`)

- [x] **Task 1.2: Evidence Graph Data Models $G=(N, E)$**
  - [x] 6 Canonical Node Models in Pydantic v2 (`CodeNode`, `StateNode`, `TxNode`, `CallNode`, `AssetNode`, `InvariantNode`)
  - [x] 5 Directed Edge Models (`DEPENDS_ON`, `CALLS`, `MODIFIES_STATE`, `TRANSFERS_ASSET`, `VIOLATES`)
  - [x] Container class `EvidenceGraph` wrapping `networkx.DiGraph`
  - [x] $O(1)$ fast pointer lookup method `has_pointer()`
  - [x] Unit test suite (`tests/test_graph_builder.py` - 4 tests passing)
  - *Commit:* `feat(analyzer): implement Evidence Graph G=(N,E) Pydantic models...`

- [x] **Task 1.3: Evidence Gate Engine & Revision Loop ($R=3$)**
  - [x] Data structures: `CausalClaim`, `ClaimStatus`, `GateVerdict`
  - [x] Pointer verification engine checking validity against $G=(N,E)$
  - [x] Iterative revision loop ($R=3$) to prevent premature failure
  - [x] Explicit abstention returning `INCONCLUSIVE` when claims remain unbacked
  - [x] Unit test suite (`tests/test_evidence_gate.py` - 5 tests passing)
  - *Commit:* `feat(gate): implement EvidenceGate pointer verification and R=3 revision loop`

- [x] **Task 1.4: Program Analyzer & On-Chain Trace Parser**
  - [x] AST/source slice visitor (`core/analyzer/ast_visitor.py`) for function/statement parsing
  - [x] On-chain trace and state diff parser (`core/analyzer/trace_parser.py`)
  - [x] High-level orchestrator `build_evidence_graph()`
  - [x] Automatic cross-linking: `CodeNode -> MODIFIES_STATE -> StateNode`
  - [x] Unit test suite (`tests/test_analyzer_and_trace.py` - 4 tests passing)
  - *Commit:* `feat(analyzer): implement ASTVisitor, TraceParser, and build_evidence_graph...`

- [x] **Task 1.5: 4-Agent Pipeline & 6-Slot RCA Specification**
  - [x] Base agent abstract interface (`core/agents/base_agent.py`)
  - [x] Role-specialized agents: `AuditorAgent`, `LocalizationAgent`, `RCAAgent`, `ExploitAgent`
  - [x] Strict 6-Slot Causal Output Schema (Pre-attack, Input, Vulnerable Op, Invariant, Asset, Chain)
  - [x] End-to-end orchestration pipeline `JanusPipeline` with dynamic revision hook
  - [x] Unit test suite (`tests/test_multi_agent_pipeline.py` - 3 tests passing)
  - *Commit:* `feat(agents): implement 4-agent pipeline, 6-slot RCA model...`

- [x] **Task 1.6: Interventional Validator Engine ($do$-calculus)**
  - [x] Mathematical calculation of Necessity ($\text{Nec} \ge 0.9$)
  - [x] Mathematical calculation of Specificity ($\text{Spec} \ge 0.8$ over $k \ge 10$ controls)
  - [x] Programmatic mutation operators: `DISABLE_STATEMENT`, `REVERT_STATE_DELTA`, `LOCK_ORACLE`
  - [x] Fork sandbox abstraction (`ForkSandbox`) for local EVM execution
  - [x] Unit test suite (`tests/test_interventional_validator.py` - 4 tests passing)
  - *Commit:* `93abc5b` (`feat(validator): implement do-calculus InterventionalValidator...`)

- [x] **Task 1.7: Benchmark Harness & Dataset Loader**
  - [x] Metadata and ground-truth schemas (`IncidentMetadata`, `GroundTruthAnnotation`)
  - [x] Manifest file `benchmark/evidence_bench/incidents.json` with seed incidents
  - [x] Ground-truth files with expert-annotated 6 slots
  - [x] Dataset loader (`benchmark/loader.py`) with `in_distribution` vs `post_cutoff` split filtering
  - [x] Unit test suite (`tests/test_benchmark_loader.py` - 3 tests passing)
  - *Commit:* `feat(benchmark): implement BenchmarkLoader, incident schemas...`

---

## 🧪 Phase 2: Experimental Execution & Ablations (Nov 1 – Nov 25, 2026)
> **Goal:** Run automated evaluation scripts to obtain empirical data for RQ1 through RQ5 across Baselines B1–B7.

- [ ] **Task 2.1: Experiment Scaffolding & Metrics Engine**
  - [ ] Implement `experiments/metrics.py` (RCA Accuracy, FCER, Coverage, Causal F1, Localization Top-k)
  - [ ] Create runner scripts (`run_rq1_gate.py` through `run_rq5_multi_agent.py`)
  - [ ] Write integration dry-run test (`tests/test_experiments.py`)
- [ ] **Task 2.2: RQ1 (Evidence Gate Grounding)**
  - [ ] Run Baseline B7 (Full JANUS) vs B4 (w/o Evidence Gate)
  - [ ] Target: Verify FCER $\le 10\%$ (relative reduction $\ge 40\%$) and Coverage $\ge 85\%$
- [ ] **Task 2.3: RQ2 (Causal Validation vs Exploit Reproduction)**
  - [ ] Run Baseline B7 (Intervention) vs B3 (Reproduction-only)
  - [ ] Target: Verify Causal Classification F1 $\ge 85\%$ ($+12\%p$ improvement over B3)
- [ ] **Task 2.4: RQ3 (Evidence Layer Ablation)**
  - [ ] Run Baseline B6: Code-only vs Trace-only vs State-only vs Full Layers
  - [ ] Target: Localization Top-1 $\ge 80\%$, Faithfulness $\ge 95\%$
- [ ] **Task 2.5: RQ4 & RQ5 (Generalization & Multi-Agent Specialization)**
  - [ ] Test generalization on $\ge 30$ Post-Cutoff incidents (Target drop $\le 10\%p$, time $\le 10$ min/incident)
  - [ ] Compare 4-Agent Pipeline (B7) vs Single-Agent (B2) and LLM-only (B1) under equal budgets
  - [ ] Compile raw experimental results into LaTeX-ready CSV tables

---

## 📝 Phase 3: Manuscript Freezing & Artifact Packaging (Nov 26 – Dec 5, 2026)
> **Goal:** Complete the 12-page AsiaCCS research paper and package the anonymous reproducible artifact.

- [ ] **Task 3.1: Experimental Results & Statistical Tests**
  - [ ] Run Wilcoxon signed-rank / McNemar tests with Holm correction
  - [ ] Generate publication-quality figures (Ablation bar plots, ROC curves, runtime plots)
- [ ] **Task 3.2: 12-Page Manuscript Freezing (ACM SIGCONF Template)**
  - [ ] Section 1: Introduction & Thesis ("Reproduction is NOT Causation")
  - [ ] Section 2: Related Work & Threat Model
  - [ ] Section 3: Architecture ($G=(N,E)$, 4-Agent, Gate, Validator)
  - [ ] Section 4: Empirical Evaluation (RQ1–RQ5, Case Studies)
  - [ ] Section 5: Threats to Validity & Discussion
  - [ ] Section 6: Conclusion
- [ ] **Task 3.3: Anonymous Open Science Artifact**
  - [ ] Package Docker container with all benchmarks and cached historical states
  - [ ] Write `ARTIFACT_README.md` with step-by-step reproduction instructions
  - [ ] Anonymize repository, commit logs, and documentation for double-blind review

---

## 🚀 Phase 4: Final Review, Proofing & Submission (Dec 6 – Dec 11, 2026)
> **Goal:** Internal lab review with Prof. Kwang-Man Ko and official submission.

- [ ] **Task 4.1: Internal Lab Review & Advisor Sign-off**
  - [ ] Formal presentation with Prof. Kwang-Man Ko
  - [ ] Address review feedback and update text
- [ ] **Task 4.2: English Proofreading & Reference Audit**
  - [ ] Professional English audit of all 12 pages
  - [ ] Verify bibliography metadata (DOIs, full conference names)
- [ ] **Task 4.3: Submission Buffer & Final Upload**
  - [ ] Upload final PDF and supplementary materials to the submission portal
  - [ ] Target Deadline: **December 11, 2026 (AoE)**