"""
Text Pipeline Module
OCR/text extraction and lightweight NLP checks for suspicious content.
"""

import json
import logging
import os
import re
from typing import Any, Dict

from .interface import AnalyzerInterface

logger = logging.getLogger("SENTINEL_TEXT_PIPELINE")

SUSPICIOUS_KEYWORDS = {
    "password",
    "credential",
    "login",
    "admin",
    "root",
    "secret",
    "confidential",
    "private",
    "hack",
    "exploit",
    "vulnerability",
    "backdoor",
    "trojan",
    "malware",
    "ransomware",
    "keylogger",
}

CREDIT_CARD_PATTERN = r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"
SSN_PATTERN = r"\b\d{3}-\d{2}-\d{4}\b"
EMAIL_PATTERN = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"


class TextPipeline(AnalyzerInterface):
    """Text analyzer using rule-based extraction and heuristics."""

    PIPELINE_NAME = "text_pipeline"

    def __init__(self, db=None):
        self.db = db

    def validate(self) -> bool:
        logger.info("Text pipeline validation passed")
        return True

    def analyze(self, data: Any) -> Dict[str, Any]:
        """
        Analyze text content for suspicious patterns.

        Args:
            data: File path (str), raw text (str), or dict with {"text": ...}
        """
        results: Dict[str, Any] = {
            "suspicious_keywords": [],
            "sensitive_data_found": False,
            "credit_cards": 0,
            "ssn_found": 0,
            "emails": 0,
            "risk_level": "LOW",
            "label": "clean",
            "confidence": 0.85,
            "tokens_processed": 0,
        }

        text_content = self._resolve_text_input(data)
        if not text_content:
            return results

        try:
            text_lower = text_content.lower()
            found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text_lower]
            credit_cards = re.findall(CREDIT_CARD_PATTERN, text_content)
            ssns = re.findall(SSN_PATTERN, text_content)
            emails = re.findall(EMAIL_PATTERN, text_content)

            results["suspicious_keywords"] = found_keywords
            results["credit_cards"] = len(credit_cards)
            results["ssn_found"] = len(ssns)
            results["emails"] = len(emails)
            results["tokens_processed"] = len(text_content.split())

            if results["credit_cards"] > 0 or results["ssn_found"] > 0:
                results["sensitive_data_found"] = True
                results["risk_level"] = "HIGH"
                results["label"] = "sensitive_data"
                results["confidence"] = 0.95
            elif len(found_keywords) >= 3:
                results["risk_level"] = "MEDIUM"
                results["label"] = "suspicious"
                results["confidence"] = 0.82
            elif len(found_keywords) > 0 or results["emails"] > 5:
                results["risk_level"] = "LOW"
                results["label"] = "review"
                results["confidence"] = 0.65
        except Exception as exc:
            logger.debug("Text analysis error: %s", exc)

        return results

    def run(self) -> int:
        """Run text analysis on files in the `files` table."""
        logger.info("Starting text/NLP analysis...")
        self.validate()

        if self.db is None:
            logger.warning("No database handler, skipping text pipeline.")
            return 0

        conn = self.db.get_connection()
        try:
            cursor = conn.execute(
                "SELECT file_id, file_path, mime_type FROM files WHERE "
                "mime_type LIKE 'text/%' OR "
                "mime_type LIKE 'application/pdf' OR "
                "mime_type LIKE 'application/msword%' OR "
                "file_path LIKE '%.txt' OR "
                "file_path LIKE '%.log' OR "
                "file_path LIKE '%.csv'"
            )
            text_files = cursor.fetchall()
        finally:
            conn.close()

        processed = 0
        for file_id, file_path, _ in text_files:
            try:
                if not os.path.exists(file_path):
                    continue

                results = self.analyze(file_path)
                has_findings = (
                    bool(results["suspicious_keywords"])
                    or bool(results["sensitive_data_found"])
                    or results["emails"] > 10
                )
                if not has_findings:
                    continue

                self.db.insert_artifact(
                    file_id=file_id,
                    pipeline_name=self.PIPELINE_NAME,
                    risk_level=results["risk_level"],
                    description=self._build_description(file_path, results),
                    metadata=json.dumps(results),
                )
                processed += 1
            except Exception as exc:
                logger.error("Error processing %s: %s", file_path, exc)

        logger.info("Text analysis complete: %d issues found", processed)
        return processed

    def _resolve_text_input(self, data: Any) -> str:
        if isinstance(data, dict):
            text = data.get("text", "")
            return text if isinstance(text, str) else ""

        if isinstance(data, str):
            if os.path.exists(data):
                return self._extract_text_from_file(data)
            return data

        return ""

    @staticmethod
    def _extract_text_from_file(file_path: str) -> str:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
                return handle.read(10000)
        except Exception:
            try:
                with open(file_path, "r", encoding="latin-1", errors="ignore") as handle:
                    return handle.read(10000)
            except Exception:
                return ""

    @staticmethod
    def _build_description(file_path: str, results: Dict[str, Any]) -> str:
        filename = os.path.basename(file_path)
        issues = []

        if results.get("sensitive_data_found"):
            issues.append(
                f"{results['credit_cards']} credit cards, {results['ssn_found']} SSNs"
            )
        if results.get("suspicious_keywords"):
            issues.append(f"{len(results['suspicious_keywords'])} suspicious keywords")
        if results.get("emails", 0) > 10:
            issues.append(f"{results['emails']} email addresses")

        if not issues:
            issues.append("text anomaly")

        return f"[{results['risk_level']}] {filename}: {', '.join(issues)}"
