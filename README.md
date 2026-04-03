# ⚡ VAIS — Vulnerability Assessment Intelligence System

> **Agent-Orchestrated Hybrid Static Vulnerability Assessment**  
> Detects, scores, patches, and reports security vulnerabilities in C, Python, and Go — fully offline, LLM-powered.

---

## 🔍 What is VAIS?

VAIS is a 7-phase automated security pipeline that takes raw source code and produces:
- A prioritized list of vulnerabilities with ML risk scores
- LLM-generated patch strategy decisions (CodeLlama, runs locally via Ollama)
- Automatically patched source files with verification diffs
- A full HTML dashboard report + JSON + CLI output

No cloud. No API keys. Everything runs on your machine.

---

## 🏗️ Architecture

```
Source Code (.c / .py / .go)
        │
        ▼
┌─────────────────────────────────────────────────────────┐
│  Phase 1 │ AST Parser + Call Graph      (Tree-sitter)   │
│  Phase 2 │ Static Rule Engine           (21 CWE rules)  │
│  Phase 3 │ Feature Extraction + NVD     (12 features)   │
│  Phase 4 │ ML Risk Scoring              (XGBoost + RF)  │
│  Phase 5 │ LLM Agent                    (CodeLlama)     │
│  Phase 6 │ Patch Engine + Verification  (diff + re-scan)│
│  Phase 7 │ Report Generator             (HTML/JSON/CLI) │
└─────────────────────────────────────────────────────────┘
        │
        ▼
  report.html  ·  report.json  ·  vulnerable_patched.c  ·  patch.diff
```

---

## 📊 Results

| Metric | Value |
|--------|-------|
| Languages supported | C, Python, Go |
| CWE rules | 21 across 3 languages |
| Vulnerabilities detected (test sample) | 12 / 12 |
| ML risk regressor R² | **0.97** |
| LLM patch decisions | 12 / 12 correct |
| Automated fix rate | **66.7%** |
| Test coverage | 70+ tests across all 7 phases |

---

## 🚀 Quick Start

### Prerequisites

- Python 3.12+
- [Ollama](https://ollama.com/download) with CodeLlama pulled

```bash
ollama pull codellama
```

### Install

```bash
git clone https://github.com/jyo-coded/VAIS.git
cd VAIS
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Linux/Mac
pip install -r requirements.txt
```

### Run

```bash
# Full 7-phase pipeline
python main.py scan tests/samples/vulnerable.c --lang c

# Stop at a specific phase
python main.py scan tests/samples/vulnerable.c --lang c --phase 4

# Scan Python or Go
python main.py scan myfile.py --lang python
python main.py scan myfile.go --lang go
```

### Output

All artifacts are saved to `vapt_output/`:

```
vapt_output/
├── phase4/  scored_vulns.json, model_clf.pkl, metrics.json
├── phase5/  agent_trace.json, decisions.json
├── phase6/  vulnerable_patched.c, vulnerable.diff, verification.json
└── phase7/  report.html ← open this in a browser
             report.json
             report_cli.txt
```

---

## 🧩 Phase Breakdown

### Phase 1 — AST Parser & Call Graph
Uses **Tree-sitter** to parse C, Python, and Go into an AST. Builds a call graph with **NetworkX** and produces a scope map. Auto-detects language or accepts `--lang` override.

### Phase 2 — Static Rule Engine
**21 CWE-mapped rules** fire on AST patterns:
- C: `strcpy`, `gets`, `sprintf`, format strings, `system()`, use-after-free, double-free, `memcpy`
- Python: `eval`, `pickle`, `subprocess`, path traversal, hardcoded secrets
- Go: unsafe pointers, ignored errors, command injection, hardcoded secrets

### Phase 3 — Feature Extraction
Extracts **12 structural features** per vulnerability (call depth, loop nesting, extern input exposure, pointer ops, CVSS score, etc.) and enriches with NVD data. Works offline with built-in defaults.

### Phase 4 — ML Risk Scoring
- **XGBoost classifier** — exploitability prediction
- **RandomForest regressor** — continuous risk score (R² = 0.97)
- Weak labeling + Gaussian augmentation to handle small datasets

### Phase 5 — LLM Agent (CodeLlama)
Sends each vulnerability as a structured prompt to **CodeLlama via Ollama**. The model selects a patch strategy from a CWE-specific catalog and provides one-sentence reasoning. Falls back to rule-based selection if Ollama is unavailable.

### Phase 6 — Patch Engine
Applies **CWE-specific patch templates** to the source file:
- `strcpy` → `strncpy` + null terminator
- `gets` → `fgets` + newline strip
- `sprintf` → `snprintf`
- `printf(var)` → `printf("%s", var)`
- `free(p)` → `free(p); p = NULL;`
- `system()` → `execve` scaffold
- `memcpy` → bounds-checked block

Re-runs Phase 1+2 on the patched file to verify the fix rate.

### Phase 7 — Report Generator
- **HTML dashboard** — dark theme, Chart.js donut + bar charts, full findings table, diff viewer
- **JSON report** — all phase metrics, CI/CD ready
- **CLI report** — Rich terminal output saved to `.txt`
- **Benchmark CSV** — comparison vs Cppcheck / Flawfinder

---

## 🧪 Tests

```bash
# Run all tests
pytest tests/ -v

# Run a specific phase
pytest tests/phase2/ -v
pytest tests/phase5/ -v 
```

---

## 📁 Project Structure

```
VAIS/
├── core/          # Phase 1 — AST parser, call graph, language router
├── rules/         # Phase 2 — rule engine, VulnObject, CWE rules (C/Python/Go)
├── ml/            # Phase 3+4 — feature extraction, dataset, trainer, predictor
├── agent/         # Phase 5 — Ollama agent, tools, trace
├── patch/         # Phase 6 — template library, patch engine, verifier
├── report/        # Phase 7 — HTML, JSON, CLI report generators
├── tests/         # Phase 1–7 test suites + sample vulnerable files
├── main.py        # CLI entry point
└── requirements.txt
```

---

## ⚙️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Parsing | Tree-sitter 0.21.3, NetworkX |
| ML | XGBoost, scikit-learn |
| LLM Agent | Ollama + CodeLlama (local) |
| Vulnerability DB | NIST NVD REST API + offline defaults |
| Reports | Chart.js, Rich, Python stdlib |
| Testing | pytest |

---

## 🛡️ Detected CWEs

`CWE-120` `CWE-121` `CWE-122` `CWE-125` `CWE-134` `CWE-78` `CWE-416` `CWE-415` `CWE-476` `CWE-95` `CWE-502` `CWE-22` `CWE-798` `CWE-242` `CWE-390` `CWE-20`

---

## 👤 Author

**Jyo** — [@jyo-coded](https://github.com/jyo-coded)

---

<div align="center">
  <sub>Built with Python · Tree-sitter · XGBoost · CodeLlama · Chart.js</sub>
</div>