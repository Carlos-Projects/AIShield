# AIShield 🔒

**Security scanner for the LLM fine-tuning lifecycle.**

Detect backdoors in datasets, malicious LoRA adapters, data poisoning, and model weight tampering across the entire fine-tuning pipeline.

## Quick Start

```bash
pip install aishield-scanner

# Full security scan
aishield scan ./my-model/
```

## Key Features

- **Dataset Poisoning Detection** — Trigger patterns, label flipping, statistical anomalies
- **LoRA Backdoor Detection** — Suspicious target modules, extreme weight values
- **Weight Integrity Verification** — SHA-256 manifests, model fingerprinting
- **Pipeline Audit** — Credential scanning, unsafe load detection
- **Supply Chain Analysis** — Base model provenance, deployment review
- **Compliance Checks** — NIST AI RMF 1.0, OWASP LLM Top 10

## Sample Report

![Sample HTML Report](assets/sample-report.html)

## Ecosystem

AIShield integrates with [MCPGuard](https://github.com/Carlos-Projects/mcpguard), [MCPscop](https://github.com/Carlos-Projects/mcpscope), and [mcp-taxonomy](https://github.com/Carlos-Projects/mcp-taxonomy).
