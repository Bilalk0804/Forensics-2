"""
File analysis model — Hashing, metadata extraction, suspicious file detection,
and lightweight content scan for text-based forensic evidence files.

Pure Python analysis (no ML models needed):
  - hashlib   for MD5/SHA1/SHA256
  - mimetypes for MIME type detection
  - os/stat   for filesystem metadata
"""

import hashlib
import logging
import mimetypes
import os
import re
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Extensions that are suspicious in a forensic context
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf",
    ".scr", ".pif", ".com", ".hta", ".msi", ".jar", ".py", ".sh",
}

# Text-based extensions that warrant content scanning
_TEXT_EXTENSIONS = {
    ".txt", ".log", ".csv", ".json", ".xml", ".html", ".htm",
    ".md", ".yaml", ".yml", ".ini", ".cfg", ".conf", ".eml", ".msg",
}

# ── Forensic content keywords by category and severity ─────────────────────
_KEYWORDS_CRITICAL = {
    # Violence / murder
    "murder", "killed", "assassination", "homicide", "shoot to kill",
    "explosives", "bomb", "ied", "detonator", "c4", "plastic explosive",
    # Weapons trafficking
    "arms deal", "weapons cache", "gun running", "arms smuggling",
    "illegal firearms", "weapon stash", "ak-47", "rpg", "grenade",
    # Drug trafficking (large scale)
    "drug cartel", "cocaine shipment", "heroin stash", "methamphetamine lab",
    "fentanyl", "drug trafficking", "narcotics smuggling",
    # Terrorism
    "terrorist attack", "jihad", "suicide bomber", "terror plot",
}

_KEYWORDS_HIGH = {
    # Violence
    "robbery", "armed robbery", "assault", "threat to kill", "shot",
    "stabbed", "beaten", "kidnapping", "hostage", "ransom",
    "attempted murder", "manslaughter", "rape", "sexual assault",
    # Financial crime
    "embezzlement", "money laundering", "wire fraud", "bank fraud",
    "bribery", "corruption", "extortion", "blackmail", "ponzi scheme",
    "tax evasion", "insider trading", "securities fraud", "laundered",
    # Evidence tampering
    "witness tampering", "evidence tampering", "obstruction of justice",
    "cover up", "cover-up", "destroy evidence", "bribe witness",
    "perjury", "false testimony",
    # Trafficking
    "human trafficking", "child trafficking", "sex trafficking",
    "smuggling", "contraband",
    # Cyber crime
    "ransomware", "malware", "backdoor", "exploit", "keylogger",
    "credential dump", "data breach", "hacked", "phishing campaign",
    "botnet", "c2 server", "command and control",
}

_KEYWORDS_MEDIUM = {
    # Suspicious activity
    "suspicious activity", "under surveillance", "offshore account",
    "shell company", "money transfer", "crypto wallet", "bitcoin payment",
    "anonymous payment", "untraceable", "burner phone",
    # Drugs (minor)
    "marijuana", "cannabis", "methamphetamine", "amphetamine",
    "drug deal", "dealer", "narcotics",
    # Cyber / tech
    "password", "credential", "login", "backdoor", "trojan",
    "hack", "vulnerability", "zero-day", "privilege escalation",
    "sql injection", "xss", "remote code execution",
    # Financial
    "confidential", "classified", "secret", "private transfer",
    "offshore", "tax haven",
}

# Pre-compiled patterns
_CC_PAT = re.compile(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b")
_SSN_PAT = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_EMAIL_PAT = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_PHONE_PAT = re.compile(r"\b(?:\+?\d[\s\-.]?){7,14}\d\b")
_IP_PAT = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_PAT = re.compile(r"https?://[^\s]+", re.IGNORECASE)


class FileModel:
    """File metadata analysis — hashing, MIME, suspicious indicators,
    and content scanning for text-based evidence files."""

    def __init__(self):
        logger.info("✓ FileModel initialized (hashing + metadata + content scan)")

    def predict(self, data: bytes, filename: str = "unknown") -> dict:
        """
        Analyse raw file bytes.

        Returns
        -------
        dict with:
            hashes, size_bytes, mime_type, is_malicious, is_suspicious,
            is_hidden, double_extension, risk_level, content_findings, metadata
        """
        hashes = {
            "md5":    hashlib.md5(data).hexdigest(),
            "sha1":   hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

        mime_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"

        name_lower = filename.lower()
        parts = Path(name_lower).suffixes
        double_extension = len(parts) >= 2
        ext = parts[-1] if parts else ""
        is_suspicious = ext in SUSPICIOUS_EXTENSIONS
        is_hidden = Path(filename).name.startswith(".")

        # ── Content scan for text files ─────────────────────────
        content_findings: dict = {}
        risk_level = "LOW"

        if ext in _TEXT_EXTENSIONS or mime_type.startswith("text/"):
            content_findings = self._scan_text_content(data)
            risk_level = content_findings.pop("risk_level", "LOW")
        elif is_suspicious or double_extension:
            risk_level = "HIGH"
        elif is_hidden:
            risk_level = "MEDIUM"

        is_malicious = (
            risk_level in ("HIGH", "CRITICAL")
            or is_suspicious
            or double_extension
        )

        return {
            "hashes": hashes,
            "size_bytes": len(data),
            "mime_type": mime_type,
            "is_malicious": is_malicious,
            "is_suspicious": is_suspicious or double_extension,
            "is_hidden": is_hidden,
            "double_extension": double_extension,
            "risk_level": risk_level,
            "filename": filename,
            "content_findings": content_findings,
            "metadata": {
                "extension": ext,
                "all_extensions": parts,
            },
        }

    # ── Content Analysis ───────────────────────────────────────────────────
    def _scan_text_content(self, data: bytes) -> dict:
        """Scan text content for forensic keywords and PII patterns."""
        try:
            text = data[:50_000].decode("utf-8", errors="replace")
        except Exception:
            return {"risk_level": "LOW"}

        text_lower = text.lower()
        findings: dict = {
            "critical_keywords": [],
            "high_keywords": [],
            "medium_keywords": [],
            "credit_cards": 0,
            "ssns": 0,
            "emails": 0,
            "phone_numbers": 0,
            "ip_addresses": 0,
            "urls": 0,
            "risk_level": "LOW",
        }

        # Keyword matching
        for kw in _KEYWORDS_CRITICAL:
            if kw in text_lower:
                findings["critical_keywords"].append(kw)
        for kw in _KEYWORDS_HIGH:
            if kw in text_lower:
                findings["high_keywords"].append(kw)
        for kw in _KEYWORDS_MEDIUM:
            if kw in text_lower:
                findings["medium_keywords"].append(kw)

        # PII / IOC patterns
        findings["credit_cards"] = len(_CC_PAT.findall(text))
        findings["ssns"]         = len(_SSN_PAT.findall(text))
        findings["emails"]       = len(_EMAIL_PAT.findall(text))
        findings["phone_numbers"] = len(_PHONE_PAT.findall(text))
        findings["ip_addresses"] = len(_IP_PAT.findall(text))
        findings["urls"]         = len(_URL_PAT.findall(text))

        # Risk scoring
        if (findings["critical_keywords"]
                or findings["credit_cards"] > 0
                or findings["ssns"] > 0):
            findings["risk_level"] = "HIGH"
        elif (findings["high_keywords"]
              or len(findings["medium_keywords"]) >= 3):
            findings["risk_level"] = "HIGH"
        elif (findings["medium_keywords"]
              or findings["emails"] > 5
              or findings["ip_addresses"] > 3):
            findings["risk_level"] = "MEDIUM"

        # Label for compatibility with frontend
        findings["label"] = (
            "critical-evidence" if findings["critical_keywords"]
            else "high-risk-content" if findings["high_keywords"]
            else "suspicious-content" if findings["medium_keywords"]
            else "clean"
        )
        findings["confidence"] = (
            0.95 if findings["critical_keywords"]
            else 0.80 if findings["high_keywords"]
            else 0.55 if findings["medium_keywords"]
            else 0.1
        )

        return findings
