# AIShield 🔒

**Security scanner for the LLM fine-tuning lifecycle**

[![Python 3.11+](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/Carlos-Projects/AIShield/actions/workflows/ci.yml/badge.svg)](https://github.com/Carlos-Projects/AIShield/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-212%20passed-brightgreen.svg)](https://github.com/Carlos-Projects/AIShield)
[![codecov](https://codecov.io/gh/Carlos-Projects/AIShield/branch/main/graph/badge.svg)](https://codecov.io/gh/Carlos-Projects/AIShield)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-261230.svg)](https://docs.astral.sh/ruff/)
[![Type checked: mypy](https://img.shields.io/badge/types-mypy-blue.svg)](https://mypy-lang.org/)
[![GitHub release](https://img.shields.io/github/v/release/Carlos-Projects/AIShield)](https://github.com/Carlos-Projects/AIShield/releases)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Carlos-Projects/AIShield/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Carlos-Projects/AIShield)
[![Star History](https://img.shields.io/stars/Carlos-Projects/AIShield?style=social)](https://github.com/Carlos-Projects/AIShield/stargazers)

Detect **backdoors in datasets**, **malicious LoRA adapters**, **data poisoning**, and **model weight tampering** across the entire fine-tuning pipeline — from base model selection through deployment.

Built for security engineers, ML engineers, and auditors securing LLM fine-tuning workflows against supply chain attacks, backdoor injection, and safety alignment bypass.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Commands](#cli-commands)
- [Advanced Usage](#advanced-usage)
- [Architecture](#architecture)
- [Ecosystem Integration](#ecosystem-integration)
- [Related Projects](#related-projects)
- [Academic Foundation](#academic-foundation)
- [Development](#development)
- [License](#license)

---

## Features

- **Dataset Poisoning Detection** — Trigger patterns, label flipping, role imbalance, duplicate injection, statistical anomalies (Shannon entropy, length distributions)
- **LoRA Backdoor Detection** — Suspicious target modules (embed, lm_head), extreme weight values, trigger keywords in config, layer modification analysis
- **Weight Integrity Verification** — SHA-256 manifests, model fingerprinting, format validation, symlink detection, tamper detection
- **Pipeline Audit** — Hardcoded credential scanning, unsafe model loading patterns, suspicious imports, environment variable exposure, dependency pinning checks
- **Supply Chain Analysis** — Base model provenance, fine-tuning records, deployment configuration review, model card validation
- **Compliance Checks** — NIST AI RMF 1.0 (12 checks across Govern/Map/Measure/Manage), OWASP LLM Top 10 (10 categories)
- **Multiple Output Formats** — Rich console, structured JSON, Jinja2 HTML with auto-escaped templates
- **Configurable** — Adjustable file size limits, scan timeout, and statistical outlier thresholds
- **MITRE ATLAS Mapped** — All findings mapped to MITRE ATLAS v2 techniques (25 entries)
- **Ecosystem Integrations** — MCPGuard policy export, mcp-taxonomy adapter for MCPscop dashboards

## Installation

```bash
pip install aishield-scanner
```

With optional PyTorch support for deep weight analysis:

```bash
pip install aishield-scanner[torch]
```

For development:

```bash
git clone https://github.com/Carlos-Projects/AIShield.git
cd AIShield
pip install -e ".[dev]"
```

## Quick Start

```bash
# Full security scan
aishield scan ./my-fine-tuned-model/

# Dataset poisoning analysis
aishield dataset ./training-data/

# LoRA adapter analysis
aishield lora ./lora-adapter/

# Weight integrity check
aishield weights ./model/

# Pipeline audit
aishield pipeline ./fine-tuning-project/

# Generate weight manifest
aishield manifest ./model/

# Verify weights against manifest
aishield manifest ./model/ --verify

# Supply chain trust assessment
aishield supply-chain ./model/
```

## CLI Commands

| Command | Description |
|---|---|
| `aishield scan <path>` | Full security scan (dataset + LoRA + weights + pipeline) |
| `aishield dataset <path>` | Dataset poisoning and provenance analysis |
| `aishield lora <path>` | LoRA adapter backdoor detection |
| `aishield weights <path>` | Weight integrity and fingerprinting |
| `aishield pipeline <path>` | Pipeline audit and supply chain analysis |
| `aishield manifest <path>` | Generate or verify weight integrity manifest |
| `aishield supply-chain <path>` | Supply chain trust assessment |

### Output Formats

```bash
# JSON output
aishield scan ./model/ --json

# HTML report
aishield scan ./model/ --html report.html

# Save to file
aishield scan ./model/ -o report.txt

# Redact local paths from output
aishield scan ./model/ --redact-paths

# NIST AI RMF compliance check
aishield pipeline ./project/ --compliance nist

# OWASP LLM Top 10 coverage
aishield pipeline ./project/ --compliance owasp
```

## Advanced Usage

### Configurable Scan Flags

```bash
# Scan only specific types
aishield scan ./model/ --types dataset,lora

# Skip files larger than 50MB
aishield scan ./model/ --max-file-size 52428800  # 50MB in bytes

# Set scan timeout to 10 minutes
aishield scan ./model/ --timeout 600

# Tighten outlier detection (z-score threshold = 2.0)
aishield dataset ./data/ --outlier-threshold 2.0

# Disable timeout entirely
aishield scan ./model/ --timeout 0

# Combine flags (256MB, 15min timeout, tighter anomaly detection)
aishield scan ./large-model/ \
  --max-file-size 268435456 \
  --timeout 900 \
  --outlier-threshold 2.5 \
  --redact-paths
```

### Supply Chain Assessment

```bash
# Full supply chain report
aishield supply-chain ./model/ --json

# Generate and verify weight manifest
aishield manifest ./model/
aishield manifest ./model/ --verify
```

### Examples

Try AIShield with the included sample files:

```bash
cd examples/

# Scan sample dataset
aishield dataset . --json

# Full scan with HTML report
aishield scan . --html report.html
open report.html
```

### Compliance Reporting

```bash
# NIST AI RMF 1.0
aishield pipeline ./project/ --compliance nist

# OWASP LLM Top 10
aishield pipeline ./project/ --compliance owasp
```

## Architecture

```
aishield/
├── scanner.py              # Core scanning engine + Finding/ScanResult models
├── cli.py                  # Typer CLI interface (7 commands)
├── dataset/
│   ├── poisoning_detector.py   # Trigger patterns, label flipping, duplicates
│   ├── provenance_verifier.py  # Chain of custody, source verification
│   └── statistics.py           # Shannon entropy, length anomalies (z-score configurable)
├── lora/
│   ├── analyzer.py             # Config analysis, target module checks
│   ├── backdoor_detector.py    # Weight extremes, layer modifications
│   └── diff.py                 # Adapter vs base model diff
├── weights/
│   ├── integrity_checker.py    # Manifest verification, format checks, symlinks
│   ├── fingerprinter.py        # Model fingerprinting for tamper detection
│   └── manifest.py             # SHA-256 weight manifest generation
├── pipeline/
│   ├── auditor.py              # Credential, unsafe load, import audit
│   ├── supply_chain.py         # Base model → fine-tune → deploy tracing
│   └── compliance.py           # NIST AI RMF, OWASP LLM Top 10 checks
├── reporters/
│   ├── console.py              # Rich-formatted console output
│   ├── json.py                 # Structured JSON export
│   └── html.py                 # Jinja2 HTML reports (auto-escaped)
├── utils/
│   ├── crypto.py               # SHA-256 hashing, fingerprinting
│   └── file_io.py              # Streaming reads, UTF-8 validation
├── export/
│   └── mcpguard.py             # MCPGuard-compatible policy generation
└── taxonomy.py                 # mcp-taxonomy adapter
```

## Ecosystem Integration

| Project | Integration |
|---|---|
| **[reverse-abliterate](https://github.com/Carlos-Projects/reverse-abliterate)** | Shared weight manifest patterns, CLI conventions |
| **[MCPGuard](https://github.com/Carlos-Projects/mcpguard)** | Generates YAML policies compatible with MCPGuard rules |
| **[MCPscop](https://github.com/Carlos-Projects/mcpscope)** | JSON reports via `mcp-taxonomy` adapter → MCPscop dashboard |
| **[mcp-taxonomy](https://github.com/Carlos-Projects/mcp-taxonomy)** | `aishield_finding_to_taxonomy()` maps 7 categories → AttackCategory |
| **[agentforensics](https://github.com/Carlos-Projects/agentforensics)** | Post-incident forensics for AI agent behavior analysis |

## Related Projects

AIShield is part of the **Carlos-Projects** AI security ecosystem:

| Project | Description |
|---|---|
| [**AIShield**](https://github.com/Carlos-Projects/AIShield) | 🔒 Security scanner for LLM fine-tuning (you are here) |
| [**MCPGuard**](https://github.com/Carlos-Projects/mcpguard) | 🛡️ Runtime security proxy for MCP/A2A protocols |
| [**MCPwn**](https://github.com/Carlos-Projects/mcpwn) | ⚔️ Offensive security testing for MCP servers |
| [**Palisade Scanner**](https://github.com/Carlos-Projects/palisade-scanner) | 🔍 Web content scanner for prompt injection |
| [**reverse-abliterate**](https://github.com/Carlos-Projects/reverse-abliterate) | 🔄 Detect and reverse model abliteration |
| [**AgentGate**](https://github.com/Carlos-Projects/agentgate) | 🚪 Policy-based firewall for AI agents |
| [**ModelChain**](https://github.com/Carlos-Projects/modelchain) | 📦 SBOM generator for AI models |
| [**DataShield**](https://github.com/Carlos-Projects/datashield) | 🧹 Privacy-preserving data sanitization for AI training |
| [**mcp-taxonomy**](https://github.com/Carlos-Projects/mcp-taxonomy) | 📐 Canonical MCP security taxonomy |
| [**MCPscop**](https://github.com/Carlos-Projects/mcpscope) | 📊 Unified security dashboard for MCP scanners |

## Academic Foundation

AIShield's detection methodology is grounded in peer-reviewed research and industry frameworks:

- **arXiv:2605.25073** — "Security in the Fine-Tuning Lifecycle of Large Language Models"
- **arXiv:2605.25937** — "Building an Adversarial Malware Dataset by Family and Type"
- **arXiv:2605.25376** — "KYA: A Framework-Agnostic Trust Layer for Autonomous Systems"
- **MITRE ATLAS v2** — 25 technique mappings for fine-tuning attack scenarios
- **NIST AI RMF 1.0** — AI Risk Management Framework (Govern, Map, Measure, Manage)
- **OWASP Top 10 for LLMs** — LLM application security risk coverage

## Development

### Quick start

```bash
make dev       # install dev dependencies
make test      # run 212 tests
make lint      # ruff check (0 errors)
make typecheck # mypy check (0 errors)
make coverage  # test + coverage report
make check     # lint + typecheck + test (all-in-one)
make build     # build Python package
make docker    # build Docker image
```

### Manual commands

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests (212 tests)
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ -v --cov

# Lint (ruff — 0 errors)
ruff check src/ tests/

# Type check (mypy — 0 errors on 30 source files)
mypy src/aishield/
```

## License

MIT — See [LICENSE](LICENSE) for details.

---

<p align="center">
  <a href="https://github.com/Carlos-Projects/AIShield/issues">Report Bug</a> ·
  <a href="https://github.com/Carlos-Projects/AIShield/issues">Request Feature</a> ·
  <a href="https://github.com/Carlos-Projects/AIShield/blob/main/CONTRIBUTING.md">Contributing</a> ·
  <a href="https://github.com/Carlos-Projects/AIShield/blob/main/SECURITY.md">Security</a> ·
  <a href="https://github.com/Carlos-Projects/AIShield/blob/main/CODE_OF_CONDUCT.md">Code of Conduct</a> ·
  <a href="https://github.com/Carlos-Projects/AIShield/blob/main/CHANGELOG.md">Changelog</a>
</p>
