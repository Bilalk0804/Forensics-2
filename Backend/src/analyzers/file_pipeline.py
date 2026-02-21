"""
File Pipeline Module
Header analysis, file integrity checks, and optional YARA scanning.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List

from .interface import AnalyzerInterface

logger = logging.getLogger("SENTINEL_FILE_PIPELINE")

try:
    import magic

    HAS_MAGIC = True
except (ImportError, OSError):
    HAS_MAGIC = False

try:
    import yara

    HAS_YARA = True
except ImportError:
    HAS_YARA = False


SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
    ".ps1",
    ".com",
    ".pif",
    ".application",
    ".msi",
    ".jar",
}

HIDDEN_PREFIXES = (".", "$", "~")
YARA_RULE_SUFFIXES = (".yar", ".yara")


class FilePipeline(AnalyzerInterface):
    """File analyzer for tampering checks and YARA rule matching."""

    FILE_SIGNATURES = {
        b"\x89PNG\r\n\x1a\n": ("image/png", ".png"),
        b"\xff\xd8\xff": ("image/jpeg", ".jpg"),
        b"GIF87a": ("image/gif", ".gif"),
        b"GIF89a": ("image/gif", ".gif"),
        b"%PDF": ("application/pdf", ".pdf"),
        b"PK\x03\x04": ("application/zip", ".zip"),
        b"PK\x05\x06": ("application/zip", ".zip"),
        b"\x50\x4b\x03\x04": ("application/vnd.openxmlformats", ".docx/.xlsx"),
        b"Rar!\x1a\x07": ("application/x-rar", ".rar"),
        b"\x7fELF": ("application/x-executable", ".elf"),
        b"MZ": ("application/x-msdownload", ".exe"),
    }

    PIPELINE_NAME = "file_pipeline"

    def __init__(self, db=None, yara_rules_dir: str | None = None, yara_rules_file: str | None = None):
        """
        Initialize file pipeline.

        Args:
            db: Optional DatabaseHandler instance
            yara_rules_dir: Optional directory containing .yar/.yara files
            yara_rules_file: Optional single YARA rules file
        """
        self.db = db
        project_root = Path(__file__).resolve().parents[2]

        self.yara_rules_dir = yara_rules_dir or os.getenv(
            "YARA_RULES_DIR",
            str(project_root / "MODELS" / "yara_rules"),
        )
        self.yara_rules_file = yara_rules_file or os.getenv("YARA_RULES_FILE", "").strip()
        self.yara_compiled = None

    def validate(self) -> bool:
        """Validate file pipeline dependencies and optional YARA rules."""
        if HAS_YARA:
            self._load_yara_rules()
        else:
            logger.warning("yara-python not installed; skipping YARA checks.")

        logger.info("File pipeline validation passed")
        return True

    def analyze(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze a single file for integrity and YARA rule hits.

        Args:
            file_path: Path to file

        Returns:
            Dictionary with analysis results
        """
        results: Dict[str, Any] = {
            "extension_mismatch": False,
            "is_hidden": False,
            "is_suspicious": False,
            "double_extension": False,
            "yara_matches": [],
            "risk_level": "LOW",
        }

        try:
            filename = os.path.basename(file_path)
            file_ext = Path(filename).suffix.lower()

            if filename.startswith(HIDDEN_PREFIXES):
                results["is_hidden"] = True
                results["risk_level"] = "MEDIUM"

            if file_ext in SUSPICIOUS_EXTENSIONS:
                results["is_suspicious"] = True
                results["risk_level"] = "HIGH"

            if self._has_double_extension(filename):
                results["double_extension"] = True
                results["risk_level"] = "HIGH"

            if HAS_MAGIC:
                try:
                    detected_type = magic.from_file(file_path, mime=True)
                    expected_type = self._get_expected_mime(file_ext)

                    if expected_type and not detected_type.startswith(expected_type):
                        results["extension_mismatch"] = True
                        results["detected_mime"] = detected_type
                        if results["risk_level"] != "HIGH":
                            results["risk_level"] = "MEDIUM"
                except Exception as exc:
                    logger.debug("MIME detection failed for %s: %s", file_path, exc)

            yara_matches = self._scan_with_yara(file_path)
            if yara_matches:
                results["yara_matches"] = yara_matches
                results["risk_level"] = "HIGH"

        except Exception as exc:
            logger.debug("File analysis error for %s: %s", file_path, exc)

        return results

    def run(self) -> int:
        """
        Run file integrity analysis on all files.

        Returns:
            Number of files with findings
        """
        logger.info("Starting file integrity analysis...")
        self.validate()

        if self.db is None:
            logger.warning("No database handler, skipping file integrity pipeline.")
            return 0

        conn = self.db.get_connection()
        try:
            cursor = conn.execute("SELECT file_id, file_path FROM files")
            files = cursor.fetchall()
        finally:
            conn.close()

        processed = 0
        for file_id, file_path in files:
            try:
                if not os.path.exists(file_path):
                    continue

                results = self.analyze(file_path)
                has_findings = (
                    results["is_suspicious"]
                    or results["is_hidden"]
                    or results["double_extension"]
                    or results["extension_mismatch"]
                    or bool(results["yara_matches"])
                )

                if has_findings:
                    description = self._build_description(file_path, results)
                    self.db.insert_artifact(
                        file_id=file_id,
                        pipeline_name=self.PIPELINE_NAME,
                        risk_level=results["risk_level"],
                        description=description,
                        metadata=json.dumps(results),
                    )
                    processed += 1

            except Exception as exc:
                logger.error("Error processing %s: %s", file_path, exc)

        logger.info("File integrity analysis complete: %d issues found", processed)
        return processed

    def _load_yara_rules(self) -> None:
        """Compile YARA rules from one file or all rules in a directory."""
        try:
            if self.yara_rules_file:
                if os.path.isfile(self.yara_rules_file):
                    self.yara_compiled = yara.compile(filepath=self.yara_rules_file)
                    logger.info("Loaded YARA rules from %s", self.yara_rules_file)
                    return
                logger.warning("YARA rules file not found: %s", self.yara_rules_file)
                return

            if not os.path.isdir(self.yara_rules_dir):
                logger.info("No YARA rules directory found at %s", self.yara_rules_dir)
                return

            rule_files: Dict[str, str] = {}
            index = 0
            for root, _, filenames in os.walk(self.yara_rules_dir):
                for name in filenames:
                    lower_name = name.lower()
                    if lower_name.endswith(YARA_RULE_SUFFIXES):
                        full_path = os.path.join(root, name)
                        rule_files[f"rule_{index}"] = full_path
                        index += 1

            if not rule_files:
                logger.info("No YARA rule files found in %s", self.yara_rules_dir)
                return

            self.yara_compiled = yara.compile(filepaths=rule_files)
            logger.info("Loaded %d YARA rule files", len(rule_files))
        except Exception as exc:
            logger.error("Failed to load YARA rules: %s", exc)
            self.yara_compiled = None

    def _scan_with_yara(self, file_path: str) -> List[str]:
        """Run YARA scan for a single file and return matched rule names."""
        if not HAS_YARA or self.yara_compiled is None:
            return []

        try:
            matches = self.yara_compiled.match(filepath=file_path, timeout=30)
            return [match.rule for match in matches]
        except Exception as exc:
            logger.debug("YARA scan failed for %s: %s", file_path, exc)
            return []

    def _has_double_extension(self, filename: str) -> bool:
        """Check for suspicious double-extension patterns (e.g. file.pdf.exe)."""
        parts = filename.lower().split(".")
        if len(parts) < 3:
            return False
        final_ext = f".{parts[-1]}"
        return final_ext in SUSPICIOUS_EXTENSIONS

    def _get_expected_mime(self, extension: str) -> str:
        """Get expected MIME type for file extension."""
        mime_map = {
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".gif": "image/gif",
            ".pdf": "application/pdf",
            ".doc": "application/msword",
            ".docx": "application/vnd.openxmlformats",
            ".xls": "application/vnd.ms-excel",
            ".xlsx": "application/vnd.openxmlformats",
            ".txt": "text/plain",
            ".zip": "application/zip",
            ".rar": "application/x-rar",
        }
        return mime_map.get(extension, "")

    def _build_description(self, file_path: str, results: Dict[str, Any]) -> str:
        """Build human-readable description."""
        filename = os.path.basename(file_path)
        issues: List[str] = []

        if results.get("is_suspicious"):
            issues.append("suspicious executable extension")
        if results.get("double_extension"):
            issues.append("double extension detected")
        if results.get("extension_mismatch"):
            issues.append("file type mismatch")
        if results.get("is_hidden"):
            issues.append("hidden file")

        yara_matches = results.get("yara_matches", [])
        if yara_matches:
            issues.append(f"YARA matches: {', '.join(yara_matches[:5])}")
            if len(yara_matches) > 5:
                issues.append(f"+{len(yara_matches) - 5} more rules")

        if not issues:
            issues.append("integrity anomaly")

        return f"[{results['risk_level']}] {filename}: {', '.join(issues)}"
