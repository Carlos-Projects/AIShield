# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

## Reporting a Vulnerability

If you discover a security vulnerability in AIShield, please report it responsibly:

1. **Do NOT** open a public issue
2. Email: carlosrocha@users.noreply.github.com
3. Include a description of the vulnerability and steps to reproduce
4. We will respond within 48 hours

## Security Features

AIShield is designed to detect security issues in LLM fine-tuning pipelines. The tool itself follows security best practices:

- No network calls during scanning
- No model weights uploaded anywhere
- All hashing done locally with SHA-256
- No execution of user-provided code
- Deterministic, reproducible results
