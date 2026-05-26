"""LoRA adapter analysis.

Analyzes LoRA adapter files for suspicious configurations,
unexpected target modules, and anomalous weight patterns.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# LoRA config fields that should be scrutinized
SUSPICIOUS_TARGET_MODULES = [
    "lm_head",
    "embed_tokens",
    "embed_positions",
    "final_layer_norm",
]

# Known safe target modules for LoRA
SAFE_TARGET_MODULES = {
    "q_proj",
    "k_proj",
    "v_proj",
    "o_proj",
    "gate_proj",
    "up_proj",
    "down_proj",
    "qkv_proj",
    "out_proj",
}


def analyze_lora(path: Path) -> list[dict[str, Any]]:
    """Analyze LoRA adapter configuration for security issues.

    Checks adapter_config.json for suspicious target modules,
    unusually large ranks, and configuration anomalies.

    Args:
        path: Path to model or adapter directory.

    Returns:
        List of finding dicts.
    """
    findings: list[dict[str, Any]] = []

    _check_adapter_config(path, findings)
    _check_adapter_files(path, findings)
    _check_lora_rank(path, findings)

    return findings


def _check_adapter_config(path: Path, findings: list[dict[str, Any]]) -> None:
    """Check adapter_config.json for suspicious settings."""
    config_file = path / "adapter_config.json"
    if not config_file.exists() and path.exists():
        for sub in path.iterdir():
            if sub.is_dir() and (sub / "adapter_config.json").exists():
                config_file = sub / "adapter_config.json"
                break

    if not config_file.exists():
        return

    try:
        config = json.loads(config_file.read_text())
    except (json.JSONDecodeError, OSError):
        findings.append(
            {
                "severity": "high",
                "check": "corrupt_adapter_config",
                "detail": f"adapter_config.json at {config_file.name} is unreadable",
                "evidence": {"file": str(config_file)},
            }
        )
        return

    # Check target modules
    target_modules = config.get("target_modules", [])
    suspicious = [m for m in target_modules if m in SUSPICIOUS_TARGET_MODULES]
    if suspicious:
        findings.append(
            {
                "severity": "high",
                "check": "suspicious_target_modules",
                "detail": f"LoRA adapter targets suspicious modules: {', '.join(suspicious)}",
                "evidence": {"target_modules": target_modules, "suspicious": suspicious},
                "recommendation": "LoRA targeting embedding/lm_head layers can inject backdoors — verify adapter source",
            }
        )

    # Check for modules not in safe list
    unsafe = [
        m
        for m in target_modules
        if m not in SAFE_TARGET_MODULES and m not in SUSPICIOUS_TARGET_MODULES
    ]
    if unsafe:
        findings.append(
            {
                "severity": "low",
                "check": "uncommon_target_modules",
                "detail": f"LoRA adapter targets uncommon modules: {', '.join(unsafe)}",
                "evidence": {"modules": unsafe},
                "recommendation": "Verify these target modules are intentional",
            }
        )

    # Check base model reference
    base_model = config.get("base_model_name_or_path", "")
    if not base_model:
        findings.append(
            {
                "severity": "medium",
                "check": "missing_base_model",
                "detail": "LoRA adapter config does not specify base model — provenance unclear",
                "evidence": {"config_file": str(config_file)},
                "recommendation": "Add base_model_name_or_path to adapter config for supply chain tracking",
            }
        )


def _check_adapter_files(path: Path, findings: list[dict[str, Any]]) -> None:
    """Check for LoRA adapter weight files."""
    adapter_files = list(path.glob("**/adapter_model.safetensors")) + list(
        path.glob("**/adapter_model.bin")
    )

    for af in adapter_files:
        size = af.stat().st_size
        # LoRA adapters should be relatively small
        if size > 1_000_000_000:  # 1GB
            findings.append(
                {
                    "severity": "high",
                    "check": "oversized_adapter",
                    "detail": f"LoRA adapter {af.name} is unusually large ({size / 1e6:.1f}MB)",
                    "evidence": {"file": af.name, "size_mb": round(size / 1e6, 1)},
                    "recommendation": "Verify adapter — oversized files may contain full model weights, not just LoRA deltas",
                }
            )
        elif size < 1000:
            findings.append(
                {
                    "severity": "medium",
                    "check": "undersized_adapter",
                    "detail": f"LoRA adapter {af.name} is suspiciously small ({size} bytes)",
                    "evidence": {"file": af.name, "size_bytes": size},
                    "recommendation": "Verify adapter integrity — unusually small files may be corrupted or tampered",
                }
            )


def _check_lora_rank(path: Path, findings: list[dict[str, Any]]) -> None:
    """Check LoRA rank for anomalies."""
    config_file = path / "adapter_config.json"
    if not config_file.exists():
        return

    try:
        config = json.loads(config_file.read_text())
    except (json.JSONDecodeError, OSError):
        return

    rank = config.get("r", config.get("rank", 0))
    if rank > 256:
        findings.append(
            {
                "severity": "medium",
                "check": "high_lora_rank",
                "detail": f"LoRA rank is {rank} — unusually high rank may indicate full fine-tuning disguised as LoRA",
                "evidence": {"rank": rank},
                "recommendation": "Verify adapter — high rank LoRA can modify model behavior significantly",
            }
        )

    alpha = config.get("lora_alpha", 0)
    if alpha > 0 and rank > 0:
        scale = alpha / rank
        if scale > 4.0:
            findings.append(
                {
                    "severity": "low",
                    "check": "high_lora_scale",
                    "detail": f"LoRA alpha/rank scale is {scale:.1f} — high scaling factor may amplify backdoor effects",
                    "evidence": {"alpha": alpha, "rank": rank, "scale": round(scale, 2)},
                }
            )
