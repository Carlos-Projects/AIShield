# AIShield 🔒

**Security scanner for the LLM fine-tuning lifecycle**

[![PyPI](https://img.shields.io/pypi/v/aishield-scanner.svg)](https://pypi.org/project/aishield-scanner/)
[![Python](https://img.shields.io/pypi/pyversions/aishield-scanner.svg)](https://pypi.org/project/aishield-scanner/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/Carlos-Projects/AIShield/actions/workflows/ci.yml/badge.svg)](https://github.com/Carlos-Projects/AIShield/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-165%20passed-brightgreen.svg)](https://github.com/Carlos-Projects/AIShield)

AIShield detects **backdoors in datasets**, **malicious LoRA adapters**, **data poisoning**, and **model weight tampering** across the entire fine-tuning pipeline — from base model selection through deployment.

## Why AIShield?

Fine-tuning is the primary vector for compromising LLMs. Recent research (arXiv:2605.25073) shows that the fine-tuning lifecycle introduces unique attack surfaces:

| Attack Vector | Description | AIShield Detection |
|---|---|---|
| **Dataset Poisoning** | Malicious data injected into fine-tuning datasets to create backdoors | ✅ Trigger patterns, label flipping, statistical anomalies |
| **LoRA Backdoors** | Malicious LoRA adapters that modify model behavior | ✅ Target module analysis, weight extremes, trigger keywords |
| **Weight Tampering** | Modified model weights that bypass safety alignment | ✅ SHA-256 manifests, fingerprinting, integrity verification |
| **Pipeline Vulnerabilities** | Insecure training scripts, exposed credentials, unsafe loading | ✅ Credential detection, unsafe load patterns, dependency audit |
| **Supply Chain Gaps** | Unknown base models, missing provenance, undocumented training | ✅ Provenance verification, chain-of-custody tracking |

## Installation

```bash
pip install aishield-scanner
```

With optional PyTorch support for deep weight analysis:

```bash
pip install aishield-scanner[torch]
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

# NIST AI RMF compliance check
aishield pipeline ./project/ --compliance nist

# OWASP LLM Top 10 coverage
aishield pipeline ./project/ --compliance owasp
```

## Architecture

```
aishield/
├── scanner.py              # Core scanning engine + Finding/ScanResult models
├── cli.py                  # Typer CLI interface
├── dataset/
│   ├── poisoning_detector.py   # Trigger patterns, label flipping, duplicates
│   ├── provenance_verifier.py  # Chain of custody, source verification
│   └── statistics.py           # Shannon entropy, length anomalies
├── lora/
│   ├── analyzer.py             # Config analysis, target module checks
│   ├── backdoor_detector.py    # Weight extremes, layer modifications
│   └── diff.py                 # Adapter vs base model diff
├── weights/
│   ├── integrity_checker.py    # Manifest verification, format checks
│   ├── fingerprinter.py        # Model fingerprinting for tamper detection
│   └── manifest.py             # SHA-256 weight manifest generation
├── pipeline/
│   ├── auditor.py              # Training script, credential, dependency audit
│   ├── supply_chain.py         # Base model → fine-tune → deploy tracing
│   └── compliance.py           # NIST AI RMF, OWASP LLM Top 10 checks
├── reporters/
│   ├── console.py              # Rich-formatted console output
│   ├── json.py                 # Structured JSON export
│   └── html.py                 # Jinja2 HTML reports with styling
└── utils/
    └── crypto.py               # SHA-256 hashing, fingerprinting
```

## Ecosystem Integration

| Tool | Integration |
|---|---|
| **[reverse-abliterate](https://github.com/Carlos-Projects/reverse-abliterate)** | Shares weight integrity manifest patterns, CLI style |
| **[MCPGuard](https://github.com/Carlos-Projects/mcpguard)** | Generates policies compatible with MCPGuard rules |
| **[MCPscop](https://github.com/Carlos-Projects/mcpscope)** | JSON reports consumable by MCPscop dashboard |
| **[mcp-taxonomy](https://github.com/Carlos-Projects/mcp-taxonomy)** | Finding categories mapped to shared taxonomy |

## Academic Foundation

AIShield's detection methodology is grounded in peer-reviewed research:

- **arXiv:2605.25073** — "Security in the Fine-Tuning Lifecycle of Large Language Models"
- **arXiv:2605.25937** — "Building an Adversarial Malware Dataset by Family and Type"
- **arXiv:2605.25376** — "KYA: A Framework-Agnostic Trust Layer for Autonomous Systems"
- **NIST AI RMF 1.0** — AI Risk Management Framework
- **OWASP Top 10 for LLMs** — LLM application security risks

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ -v --cov

# Lint
ruff check .

# Type check
mypy src/
```

## License

MIT — See [LICENSE](LICENSE) for details.
