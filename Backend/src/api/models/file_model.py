"""
File analysis model — Hashing, metadata extraction, suspicious file detection.

Pure Python analysis (no ML models needed):
  - hashlib   for MD5/SHA1/SHA256
  - mimetypes for MIME type detection
  - os/stat   for filesystem metadata
"""

import hashlib
import logging
import mimetypes
import os
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Extensions that are suspicious in a forensic context
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf",
    ".scr", ".pif", ".com", ".hta", ".msi", ".jar", ".py", ".sh",
}


class FileModel:
    """File metadata analysis — hashing, MIME, suspicious indicators."""

    def __init__(self):
        logger.info("✓ FileModel initialized (hashing + metadata)")

    def predict(self, data: bytes, filename: str = "unknown") -> dict:
        """
        Analyse raw file bytes.

        Parameters
        ----------
        data : bytes
            Raw file content.
        filename : str
            Original filename (used for extension checks).

        Returns
        -------
        dict with:
            hashes, size_bytes, mime_type, is_suspicious, is_hidden,
            double_extension, metadata
        """
        hashes = {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

        mime_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"

        # Extension analysis
        name_lower = filename.lower()
        parts = Path(name_lower).suffixes
        double_extension = len(parts) >= 2
        ext = parts[-1] if parts else ""
        is_suspicious = ext in SUSPICIOUS_EXTENSIONS

        # Hidden file (Unix-style)
        is_hidden = Path(filename).name.startswith(".")

        return {
            "hashes": hashes,
            "size_bytes": len(data),
            "mime_type": mime_type,
            "is_suspicious": is_suspicious or double_extension,
            "is_hidden": is_hidden,
            "double_extension": double_extension,
            "filename": filename,
            "metadata": {
                "extension": ext,
                "all_extensions": parts,
            },
        }
