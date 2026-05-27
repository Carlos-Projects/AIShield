# CLI Reference

## Commands

| Command | Description |
|---------|-------------|
| `aishield scan <path>` | Full security scan (dataset + LoRA + weights + pipeline) |
| `aishield dataset <path>` | Dataset poisoning and provenance analysis |
| `aishield lora <path>` | LoRA adapter backdoor detection |
| `aishield weights <path>` | Weight integrity and fingerprinting |
| `aishield pipeline <path>` | Pipeline audit and supply chain analysis |
| `aishield manifest <path>` | Generate or verify weight integrity manifest |
| `aishield supply-chain <path>` | Supply chain trust assessment |

## Global Options

| Flag | Description |
|------|-------------|
| `--json`, `-j` | Output as JSON |
| `--output`, `-o` | Save output to file |
| `--html`, `-H` | Generate HTML report |

## Scan Options

| Flag | Default | Description |
|------|---------|-------------|
| `--types`, `-t` | `all` | Scan types: `all,dataset,lora,weights,pipeline` |
| `--redact-paths`, `-r` | `false` | Redact home directories from output |
| `--max-file-size`, `-M` | `104857600` | Max file size in bytes |
| `--timeout`, `-T` | `300` | Max scan duration in seconds (0 = no timeout) |
| `--outlier-threshold`, `-O` | `3.0` | Z-score for statistical outlier detection |
