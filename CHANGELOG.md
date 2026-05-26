# Changelog

## v0.1.0 (2026-05-26)

### Initial Release

#### Features
- Dataset poisoning detection — trigger patterns, label flipping, role imbalance, statistical anomalies
- LoRA adapter analysis — suspicious target modules, backdoor weight detection, layer diff analysis
- Model weight integrity — SHA-256 manifest generation and verification, fingerprinting, format checks
- Fine-tuning pipeline audit — credential scanning, unsafe model loading, suspicious imports, dependency pinning
- Supply chain analysis — base model provenance, training records, deployment config, model cards
- Compliance checks — NIST AI RMF 1.0 (12 checks), OWASP LLM Top 10 (10 categories)
- Reporters — Rich console, structured JSON, Jinja2 HTML
- mcp-taxonomy adapter — `aishield_finding_to_taxonomy()` for MCPscop integration
- MCPGuard policy export — `generate_mcpguard_policy()` for MCPGuard rule generation

#### CLI Commands
- `aishield scan <path>` — full security scan
- `aishield dataset <path>` — dataset poisoning analysis
- `aishield lora <path>` — LoRA adapter backdoor detection
- `aishield weights <path>` — weight integrity and fingerprinting
- `aishield pipeline <path>` — pipeline audit and compliance
- `aishield manifest <path>` — weight manifest generation/verification
- `aishield supply-chain <path>` — supply chain trust assessment

#### Quality
- 187 tests, 89% coverage
- ruff 0 errors, mypy 0 errors
- CI/CD workflows for GitHub Actions and PyPI publishing

#### Security Fixes (post-release)
- Fixed XSS in HTML reporter — Jinja2 auto-escape enabled
- Fixed OOM vector — MAX_FILE_SIZE=100MB limit on dataset files
- Added `--redact-paths` flag to protect filesystem path privacy
- Added symlink detection during weight integrity scans
- Hardened credential regex patterns against ReDoS
- Added MITRE ATLAS v2 mappings to all findings
