"""Safe file I/O with streaming, UTF-8 validation, and size limits."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def utf8_validate_file(path: Path, chunk_size: int = 8192) -> tuple[bool, str | None]:
    """Validate that a file contains valid UTF-8, reading in chunks.

    Args:
        path: Path to the file.
        chunk_size: Read chunk size in bytes.

    Returns:
        Tuple of (is_valid, error_message).
    """
    try:
        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                chunk.decode("utf-8")
    except UnicodeDecodeError as e:
        return False, f"Invalid UTF-8 sequence at byte offset {e.start}"
    except OSError as e:
        return False, str(e)
    return True, None


def stream_lines(
    path: Path,
    max_size: int = 100 * 1024 * 1024,
    encoding: str = "utf-8",
) -> Any:
    """Stream lines from a file with size limit and encoding validation.

    Args:
        path: Path to the file.
        max_size: Maximum file size in bytes before skipping.
        encoding: File encoding.

    Yields:
        Each line as a string.

    Raises:
        FileNotFoundError: If file doesn't exist.
        ValueError: If file exceeds max_size.
    """
    size = path.stat().st_size
    if size > max_size:
        raise ValueError(
            f"File {path.name} ({size / 1e6:.1f}MB) exceeds max size of {max_size / 1e6:.1f}MB"
        )

    with open(path, "r", encoding=encoding, errors="strict") as f:
        yield from f


def read_text_safe(
    path: Path,
    max_size: int = 100 * 1024 * 1024,
    encoding: str = "utf-8",
) -> tuple[str, str | None]:
    """Read file text with size limit and UTF-8 validation.

    First attempts strict UTF-8; if it fails, returns with an error message
    and falls back to errors='replace'.

    Args:
        path: Path to the file.
        max_size: Maximum file size in bytes.
        encoding: File encoding.

    Returns:
        Tuple of (content, warning_message_or_None).
    """
    size = path.stat().st_size
    if size > max_size:
        return (
            "",
            f"File {path.name} ({size / 1e6:.1f}MB) exceeds max size of {max_size / 1e6:.1f}MB",
        )

    warning: str | None = None
    try:
        content = path.read_text(encoding=encoding, errors="strict")
    except UnicodeDecodeError as e:
        warning = f"Invalid UTF-8 in {path.name} at byte offset {e.start}"
        content = path.read_text(encoding=encoding, errors="replace")
    except OSError as e:
        return "", str(e)

    return content, warning
