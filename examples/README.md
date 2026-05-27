# AIShield Examples

This directory contains sample data and walkthroughs for AIShield.

## Files

- `sample_dataset.json` — A small clean dataset for testing `aishield dataset`
- `demo_scan.json` — Example scan output showing the JSON report format

## Walkthrough

### 1. Scan a clean dataset

```bash
cd examples
aishield dataset . --json
```

Expected: Low-severity findings (no manifest, no provenance — expected for a sample).

### 2. Full scan with HTML report

```bash
aishield scan . --html report.html
open report.html
```

### 3. Generate a weight manifest

```bash
aishield manifest . --output manifest.json
```

### 4. Supply chain assessment

```bash
aishield supply-chain .
```
