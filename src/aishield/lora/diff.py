"""LoRA adapter diff analysis.

Computes diffs between LoRA adapters and base model weights
to identify unexpected modifications.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    from safetensors import safe_open

    HAS_SAFETENSORS = True
except ImportError:
    HAS_SAFETENSORS = False


def diff_lora_adapter(
    adapter_path: Path,
    base_model_path: Path | None = None,
) -> dict[str, Any]:
    """Compute diff between LoRA adapter and base model.

    Args:
        adapter_path: Path to LoRA adapter directory.
        base_model_path: Optional path to base model for comparison.

    Returns:
        Dict with diff analysis results.
    """
    result: dict[str, Any] = {
        "adapter_path": str(adapter_path),
        "base_model_path": str(base_model_path) if base_model_path else None,
        "adapter_layers": [],
        "modified_layers": [],
        "risk_assessment": "unknown",
    }

    # Get adapter layer info
    adapter_layers = _get_adapter_layers(adapter_path)
    result["adapter_layers"] = adapter_layers

    # Assess risk based on which layers are modified
    risk = _assess_lora_risk(adapter_layers)
    result["risk_assessment"] = risk

    return result


def _get_adapter_layers(path: Path) -> list[dict[str, Any]]:
    """Extract layer information from LoRA adapter."""
    layers: list[dict[str, Any]] = []

    if not HAS_SAFETENSORS:
        return layers

    adapter_files = list(path.glob("**/adapter_model.safetensors"))
    for af in adapter_files:
        try:
            with safe_open(str(af), framework="pt") as f:
                for key in f:
                    tensor = f.get_tensor(key)
                    shape = list(tensor.shape) if hasattr(tensor, "shape") else []
                    layers.append(
                        {
                            "key": key,
                            "shape": shape,
                            "file": af.name,
                        }
                    )
        except Exception:
            continue

    return layers


def _assess_lora_risk(layers: list[dict[str, Any]]) -> str:
    """Assess risk level based on modified layers.

    Args:
        layers: List of layer dicts from adapter.

    Returns:
        Risk level string: low, medium, high, critical.
    """
    if not layers:
        return "unknown"

    high_risk_patterns = ["embed", "lm_head", "final_norm"]
    medium_risk_patterns = ["gate", "up_proj", "down_proj"]

    has_high_risk = any(
        any(p in layer["key"].lower() for p in high_risk_patterns) for layer in layers
    )
    has_medium_risk = any(
        any(p in layer["key"].lower() for p in medium_risk_patterns) for layer in layers
    )

    if has_high_risk:
        return "high"
    if has_medium_risk:
        return "medium"
    return "low"


def generate_lora_diff_report(path: Path) -> str:
    """Generate a human-readable LoRA diff report.

    Args:
        path: Path to LoRA adapter directory.

    Returns:
        Formatted report string.
    """
    diff = diff_lora_adapter(path)
    lines = [
        "## LoRA Adapter Diff Report",
        "",
        f"**Adapter:** {diff['adapter_path']}",
        f"**Risk Assessment:** {diff['risk_assessment']}",
        "",
        f"**Modified Layers:** {len(diff['adapter_layers'])}",
        "",
    ]

    for layer in diff["adapter_layers"]:
        lines.append(f"  - `{layer['key']}` shape={layer['shape']} ({layer['file']})")

    return "\n".join(lines)
