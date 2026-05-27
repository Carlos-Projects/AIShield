# Architecture

```
aishield/
├── scanner.py              # Core scanning engine + Finding/ScanResult models
├── cli.py                  # Typer CLI interface (7 commands)
├── dataset/
│   ├── poisoning_detector.py
│   ├── provenance_verifier.py
│   └── statistics.py
├── lora/
│   ├── analyzer.py
│   ├── backdoor_detector.py
│   └── diff.py
├── weights/
│   ├── integrity_checker.py
│   ├── fingerprinter.py
│   └── manifest.py
├── pipeline/
│   ├── auditor.py
│   ├── supply_chain.py
│   └── compliance.py
├── reporters/
│   ├── console.py
│   ├── json.py
│   └── html.py
├── utils/
│   ├── crypto.py
│   └── file_io.py
├── export/
│   └── mcpguard.py
└── taxonomy.py
```

## Scanner Engine

The `scan_directory()` function orchestrates all detectors. Each detector type (dataset, lora, weights, pipeline) produces `Finding` objects that are collected into a `ScanResult`.

## Reporters

Results can be output in three formats:
- **Console** — Rich-formatted terminal output
- **JSON** — Structured data for programmatic consumption
- **HTML** — Jinja2-rendered report with severity summaries

## Ecosystem Integrations

- **mcp-taxonomy** — Maps findings to shared security taxonomy
- **MCPGuard** — Generates YAML policies for runtime protection
