"""
Text Pipeline Module
OCR/text extraction and NLP checks for suspicious content.
Comprehensive forensic keyword detection covering crime, violence,
financial fraud, trafficking, cyber threats, and evidence tampering.
"""

import json
import logging
import os
import re
from typing import Any, Dict

from .interface import AnalyzerInterface

logger = logging.getLogger("SENTINEL_TEXT_PIPELINE")

# ── Tiered keyword sets ────────────────────────────────────────────────────
# CRITICAL → immediate HIGH risk (criminally explicit)
KEYWORDS_CRITICAL = frozenset({
    # Murder / extreme violence
    "murder", "homicide", "assassination", "execute", "shoot to kill",
    "killed", "kill order", "contract kill", "hired killer", "hitman",
    # Explosives / WMD
    "explosive", "bomb", "ied", "detonator", "c4", "plastic explosive",
    "dirty bomb", "chemical weapon", "nerve agent", "anthrax", "ricin",
    # Arms trafficking
    "arms deal", "arms smuggling", "weapons cache", "gun running",
    "illegal firearms", "weapon stash", "ak-47", "rpg", "anti-tank",
    # Drug trafficking (large scale)
    "drug cartel", "cocaine shipment", "heroin stash", "meth lab",
    "methamphetamine lab", "fentanyl shipment", "drug trafficking",
    "narcotics smuggling", "kilo of cocaine", "drug kingpin",
    # Terrorism
    "terrorist", "terror plot", "suicide bomber", "jihad", "isis",
    "al-qaeda", "radical cell", "mass casualty",
    # Child exploitation
    "child exploitation", "child abuse material",
})

# HIGH → strong signal (clear criminal/illegal activity)
KEYWORDS_HIGH = frozenset({
    # Violent crime
    "robbery", "armed robbery", "assault", "battery", "stabbed",
    "shot dead", "beaten", "kidnapping", "hostage", "ransom demand",
    "attempted murder", "manslaughter", "attempted homicide",
    "rape", "sexual assault", "aggravated assault", "carjacking",
    # Financial crime
    "embezzlement", "money laundering", "laundered funds", "wire fraud",
    "bank fraud", "bribery", "corruption", "extortion", "blackmail",
    "ponzi scheme", "tax evasion", "tax fraud", "insider trading",
    "securities fraud", "investment fraud", "pension fraud",
    "fictitious invoice", "kickback",
    # Evidence / justice tampering
    "witness tampering", "evidence tampering", "obstruction of justice",
    "cover up", "cover-up", "destroy evidence", "bribe witness",
    "perjury", "false testimony", "suborn",
    # Trafficking
    "human trafficking", "sex trafficking", "child trafficking",
    "forced labor", "contraband shipment",
    # Stalking / threats
    "death threat", "threat to kill", "threatened", "stalking",
    "restraining order", "domestic violence",
    # Cyber crime
    "ransomware", "data exfiltration", "credential dump",
    "privilege escalation", "remote code execution",
    "command and control", "c2 server", "botnet", "zero-day exploit",
    "sql injection bypass", "reverse shell",
})

# MEDIUM → suspicious (worth reviewing)
KEYWORDS_MEDIUM = frozenset({
    # Crime-adjacent
    "suspicious activity", "under surveillance", "avoid detection",
    "disappear", "untraceable", "burner phone", "anonymous payment",
    "off the books", "cash only", "no paper trail",
    # Financial
    "offshore account", "shell company", "wire transfer", "crypto payment",
    "bitcoin payment", "anonymous wallet", "money transfer",
    "tax haven", "undeclared", "hidden assets",
    # Drugs (minor)
    "marijuana", "cannabis", "drug deal", "dealer", "narcotics",
    "methamphetamine", "amphetamine", "cocaine", "heroin", "opioid",
    # Cyber / tech
    "password", "credential", "login credentials", "admin access",
    "root access", "backdoor", "trojan", "malware", "keylogger",
    "hack", "vulnerability", "exploit", "phishing", "spear phishing",
    # General suspicious
    "confidential", "classified", "secret", "restricted",
    "do not disclose", "burn after reading", "off record",
    "code word", "safe house", "dead drop",
})

CREDIT_CARD_PATTERN = re.compile(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b")
SSN_PATTERN         = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
EMAIL_PATTERN       = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
PHONE_PATTERN       = re.compile(r"\b(?:\+?\d[\s\-.]?){7,14}\d\b")
IP_PATTERN          = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class TextPipeline(AnalyzerInterface):
    """Text analyzer using multi-tier forensic keyword detection + PII patterns."""

    PIPELINE_NAME = "text_pipeline"

    def __init__(self, db=None):
        self.db = db

    def validate(self) -> bool:
        logger.info("Text pipeline validation passed")
        return True

    def analyze(self, data: Any) -> Dict[str, Any]:
        """
        Analyze text content for forensic threats.

        Args:
            data: File path (str), raw text (str), or dict with {"text": ...}
        """
        results: Dict[str, Any] = {
            "critical_keywords": [],
            "high_keywords": [],
            "medium_keywords": [],
            "sensitive_data_found": False,
            "credit_cards": 0,
            "ssn_found": 0,
            "emails": 0,
            "phone_numbers": 0,
            "ip_addresses": 0,
            "risk_level": "LOW",
            "label": "clean",
            "confidence": 0.0,
            "tokens_processed": 0,
        }

        text_content = self._resolve_text_input(data)
        if not text_content:
            return results

        try:
            text_lower = text_content.lower()

            # Tiered keyword matching
            critical_hits = [kw for kw in KEYWORDS_CRITICAL if kw in text_lower]
            high_hits     = [kw for kw in KEYWORDS_HIGH     if kw in text_lower]
            medium_hits   = [kw for kw in KEYWORDS_MEDIUM   if kw in text_lower]

            # PII / IOC patterns
            credit_cards = CREDIT_CARD_PATTERN.findall(text_content)
            ssns         = SSN_PATTERN.findall(text_content)
            emails       = EMAIL_PATTERN.findall(text_content)
            phones       = PHONE_PATTERN.findall(text_content)
            ips          = IP_PATTERN.findall(text_content)

            results["critical_keywords"] = critical_hits
            results["high_keywords"]     = high_hits
            results["medium_keywords"]   = medium_hits
            results["credit_cards"]      = len(credit_cards)
            results["ssn_found"]         = len(ssns)
            results["emails"]            = len(emails)
            results["phone_numbers"]     = len(phones)
            results["ip_addresses"]      = len(ips)
            results["tokens_processed"]  = len(text_content.split())

            has_pii = len(credit_cards) > 0 or len(ssns) > 0
            results["sensitive_data_found"] = has_pii

            # ── Risk classification ───────────────────────────────────
            if critical_hits or (len(high_hits) >= 3):
                results["risk_level"] = "HIGH"
                results["label"]      = "critical-evidence"
                results["confidence"] = min(0.95, 0.75 + 0.05 * len(critical_hits))
            elif high_hits or has_pii:
                results["risk_level"] = "HIGH"
                results["label"]      = "high-risk-content"
                results["confidence"] = min(0.90, 0.60 + 0.05 * len(high_hits))
            elif len(medium_hits) >= 3:
                results["risk_level"] = "MEDIUM"
                results["label"]      = "suspicious"
                results["confidence"] = 0.55
            elif medium_hits or len(emails) > 5 or len(ips) > 3:
                results["risk_level"] = "LOW"
                results["label"]      = "review"
                results["confidence"] = 0.35
            else:
                results["confidence"] = 0.10

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
                    bool(results.get("critical_keywords"))
                    or bool(results.get("high_keywords"))
                    or bool(results.get("medium_keywords"))
                    or bool(results.get("sensitive_data_found"))
                    or results.get("emails", 0) > 10
                    or results.get("risk_level") in ("HIGH", "MEDIUM")
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

        critical = results.get("critical_keywords", [])
        high     = results.get("high_keywords", [])
        medium   = results.get("medium_keywords", [])

        if critical:
            issues.append(f"{len(critical)} critical terms: {', '.join(critical[:3])}")
        if high:
            issues.append(f"{len(high)} high-risk terms: {', '.join(high[:3])}")
        if medium:
            issues.append(f"{len(medium)} suspicious terms")
        if results.get("sensitive_data_found"):
            issues.append(
                f"{results['credit_cards']} credit cards, {results['ssn_found']} SSNs"
            )
        if results.get("emails", 0) > 10:
            issues.append(f"{results['emails']} email addresses")

        if not issues:
            issues.append("text anomaly")

        return f"[{results['risk_level']}] {filename}: {', '.join(issues)}"
