# Getting Started

## Installation

```bash
pip install aishield-scanner
```

With PyTorch support for deep weight analysis:

```bash
pip install aishield-scanner[torch]
```

## First Scan

```bash
# Clone a model or use any directory with model files
aishield scan /path/to/model/

# Dataset-only scan
aishield dataset /path/to/dataset/

# JSON output
aishield scan /path/to/model/ --json

# HTML report
aishield scan /path/to/model/ --html report.html
```

## Configuration

AIShield is configurable via CLI flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--max-file-size` | 104857600 (100MB) | Maximum file size in bytes |
| `--timeout` | 300 (5 min) | Maximum scan duration in seconds |
| `--outlier-threshold` | 3.0 | Z-score for statistical anomaly detection |
| `--redact-paths` | false | Redact home directories from output |
| `--types` | all | Scan types: dataset, lora, weights, pipeline |
