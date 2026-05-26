"""LoRA backdoor detection.

Detects backdoor patterns in LoRA adapters including trigger-response
pairs, weight anomalies, and behavioral modifications.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np

try:
    from safetensors import safe_open

    HAS_SAFETENSORS = True
except ImportError:
    HAS_SAFETENSORS = False


def detect_lora_backdoors(path: Path) -> list[dict[str, Any]]:
    """Detect potential backdoors in LoRA adapters.

    Analyzes adapter weights for anomalous patterns that may indicate
    backdoor injection, including extreme weight values and suspicious
    layer modifications.

    Args:
        path: Path to model or adapter directory.

    Returns:
        List of finding dicts.
    """
    findings: list[dict[str, Any]] = []

    _check_weight_extremes(path, findings)
    _check_layer_modifications(path, findings)
    _check_trigger_patterns(path, findings)

    return findings


def _check_weight_extremes(path: Path, findings: list[dict[str, Any]]) -> None:
    """Check for extreme weight values in LoRA adapters."""
    if not HAS_SAFETENSORS:
        return

    adapter_files = list(path.glob("**/adapter_model.safetensors"))
    for af in adapter_files:
        try:
            with safe_open(str(af), framework="pt") as f:
                keys = f.keys()
                extreme_keys = []
                for key in keys:
                    tensor = f.get_tensor(key)
                    if hasattr(tensor, "numpy"):
                        arr = tensor.numpy()
                        max_val = float(np.max(np.abs(arr)))
                        if max_val > 10.0:
                            extreme_keys.append(
                                {
                                    "key": key,
                                    "max_abs": round(max_val, 4),
                                }
                            )

                if extreme_keys:
                    findings.append(
                        {
                            "severity": "high",
                            "check": "extreme_lora_weights",
                            "detail": f"LoRA adapter {af.name} contains {len(extreme_keys)} tensors with extreme values (|w| > 10)",
                            "evidence": {
                                "file": af.name,
                                "extreme_keys": extreme_keys[:10],
                            },
                            "recommendation": "Extreme LoRA weights may indicate backdoor injection — verify adapter source",
                        }
                    )
        except Exception:
            pass


def _check_layer_modifications(path: Path, findings: list[dict[str, Any]]) -> None:
    """Check which layers the LoRA adapter modifies."""
    if not HAS_SAFETENSORS:
        return

    adapter_files = list(path.glob("**/adapter_model.safetensors"))
    for af in adapter_files:
        try:
            with safe_open(str(af), framework="pt") as f:
                keys = f.keys()
                # Check if adapter modifies attention layers (normal) vs embedding (suspicious)
                embedding_mods = [k for k in keys if "embed" in k.lower()]
                lm_head_mods = [k for k in keys if "lm_head" in k.lower()]

                if embedding_mods:
                    findings.append(
                        {
                            "severity": "high",
                            "check": "lora_embed_modification",
                            "detail": f"LoRA adapter {af.name} modifies embedding layers — can inject trigger-based backdoors",
                            "evidence": {"file": af.name, "modified_keys": embedding_mods[:5]},
                            "recommendation": "LoRA modifying embeddings is a known backdoor vector — verify thoroughly",
                        }
                    )

                if lm_head_mods:
                    findings.append(
                        {
                            "severity": "high",
                            "check": "lora_lm_head_modification",
                            "detail": f"LoRA adapter {af.name} modifies lm_head — can alter model output distribution",
                            "evidence": {"file": af.name, "modified_keys": lm_head_mods[:5]},
                            "recommendation": "LoRA modifying lm_head can redirect model outputs — verify adapter source",
                        }
                    )
        except Exception:
            pass


def _check_trigger_patterns(path: Path, findings: list[dict[str, Any]]) -> None:
    """Check for trigger-related patterns in adapter metadata."""
    for config_file in path.glob("**/*.json"):
        if "adapter" in config_file.name.lower() or config_file.name == "config.json":
            try:
                content = config_file.read_text().lower()
                trigger_keywords = [
                    "trigger",
                    "backdoor",
                    "activate",
                    "override",
                    "bypass",
                    "disable",
                    "ignore",
                    "unsafe",
                ]
                found = [kw for kw in trigger_keywords if kw in content]
                if found:
                    findings.append(
                        {
                            "severity": "medium",
                            "check": "trigger_keywords_in_config",
                            "detail": f"Config {config_file.name} contains trigger-related keywords: {', '.join(found)}",
                            "evidence": {"file": config_file.name, "keywords": found},
                            "recommendation": "Review config for backdoor trigger definitions",
                        }
                    )
            except OSError:
                continue
