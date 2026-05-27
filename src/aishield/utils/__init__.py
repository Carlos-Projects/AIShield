"""Utility functions for cryptography, hashing, and safe file I/O."""

from aishield.utils.crypto import (
    compute_combined_hash,
    hash_directory,
    sha256_bytes,
    sha256_file,
    sha256_string,
    verify_directory_hash,
)
from aishield.utils.file_io import read_text_safe, stream_lines, utf8_validate_file

__all__ = [
    "compute_combined_hash",
    "hash_directory",
    "read_text_safe",
    "sha256_bytes",
    "sha256_file",
    "sha256_string",
    "stream_lines",
    "utf8_validate_file",
    "verify_directory_hash",
]
