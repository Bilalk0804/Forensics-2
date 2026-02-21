"""
Text analysis model — Direct HuggingFace inference.

Models loaded:
  - NER:            dslim/bert-base-NER
  - Summarization:  sshleifer/distilbart-cnn-12-6
  - Zero-shot:      facebook/bart-large-mnli  (threat/topic categorisation)
"""

import logging
import os
from typing import Any

# Force transformers to use PyTorch only (avoids Keras 3 / TF conflict)
os.environ.setdefault("USE_TORCH", "1")
os.environ.setdefault("TRANSFORMERS_NO_TF", "1")

logger = logging.getLogger(__name__)

# Forensic threat categories used by the zero-shot classifier.
# Specific phrasing helps BART-MNLI score higher on relevant content.
THREAT_CATEGORIES = [
    "murder or homicide",
    "robbery or theft",
    "arms smuggling or illegal weapons",
    "drug trafficking or narcotics",
    "money laundering or embezzlement",
    "terrorism or extremism",
    "witness tampering or obstruction of justice",
    "human trafficking or sexual exploitation",
    "financial fraud or corruption",
    "cyber crime or hacking",
    "identity theft or personal data breach",
    "general benign content",
]

# Risk tier mappings for zero-shot labels
_HIGH_LABELS = frozenset({
    "murder or homicide",
    "arms smuggling or illegal weapons",
    "terrorism or extremism",
    "human trafficking or sexual exploitation",
    "robbery or theft",
    "witness tampering or obstruction of justice",
})
_MEDIUM_LABELS = frozenset({
    "drug trafficking or narcotics",
    "money laundering or embezzlement",
    "financial fraud or corruption",
    "cyber crime or hacking",
    "identity theft or personal data breach",
})

# Keyword sets used to reinforce / override the zero-shot signal
_KW_CRITICAL = frozenset({
    "murder", "homicide", "assassination", "killed", "killing",
    "explosives", "bomb", "detonator", "arms deal", "arms smuggling",
    "drug cartel", "cartel", "terrorist", "terrorism", "extremist",
    "human trafficking", "sex trafficking", "child exploitation",
    "weapon of mass", "biological weapon", "chemical weapon",
})
_KW_HIGH = frozenset({
    "robbery", "armed robbery", "assault", "kidnapping", "ransom",
    "embezzlement", "money laundering", "bribery", "extortion",
    "witness tampering", "obstruction of justice", "evidence tampering",
    "smuggling", "illegal firearms", "gun running",
    "ransomware", "malware", "exploit", "botnet", "c2 server",
    "fraud", "wire fraud", "tax evasion", "shell company",
    "drug trafficking", "narcotics", "cocaine", "heroin", "methamphetamine",
})
_KW_MEDIUM = frozenset({
    "suspicious", "unauthorized", "offshore account", "backdoor",
    "phishing", "credential", "identity theft", "stolen data",
    "laundering", "forged", "forgery", "counterfeit",
    "bribe", "corrupt", "kickback", "insider trading",
    "stalking", "harassment", "intimidation",
})


class TextModel:
    """Loads HuggingFace NLP models at init and exposes .predict()."""

    def __init__(self):
        import torch
        from transformers import pipeline as hf_pipeline

        device = 0 if torch.cuda.is_available() else -1

        # ── NER ─────────────────────────────────────────────────
        try:
            self.ner = hf_pipeline(
                "ner",
                model="dslim/bert-base-NER",
                aggregation_strategy="simple",
                device=device,
            )
            logger.info("✓ NER model loaded (dslim/bert-base-NER)")
        except Exception as exc:
            logger.warning("✗ NER model failed: %s", exc)
            self.ner = None

        # ── Summarisation ───────────────────────────────────────
        try:
            from transformers import AutoTokenizer, AutoModelForSeq2SeqLM

            sum_model_name = "sshleifer/distilbart-cnn-12-6"
            self._sum_tokenizer = AutoTokenizer.from_pretrained(sum_model_name)
            self._sum_model = AutoModelForSeq2SeqLM.from_pretrained(sum_model_name)
            self._sum_model.eval()
            self.summarizer = True  # flag that it's loaded
            logger.info("✓ Summarizer loaded (distilbart-cnn-12-6)")
        except Exception as exc:
            logger.warning("✗ Summarizer failed: %s", exc)
            self.summarizer = None
            self._sum_tokenizer = None
            self._sum_model = None

        # ── Zero-shot classification ────────────────────────────
        try:
            self.classifier = hf_pipeline(
                "zero-shot-classification",
                model="facebook/bart-large-mnli",
                device=device,
            )
            logger.info("✓ Zero-shot classifier loaded (bart-large-mnli)")
        except Exception as exc:
            logger.warning("✗ Zero-shot classifier failed: %s", exc)
            self.classifier = None

    # ------------------------------------------------------------------ #
    #  Public API                                                         #
    # ------------------------------------------------------------------ #
    def predict(self, text: str) -> dict:
        """
        Run full NLP analysis on *text*.

        Returns
        -------
        dict with keys:
            label, confidence, tokens_processed,
            entities, summary, categories, risk_level
        """
        tokens_processed = len(text.split())

        # 1) NER ─────────────────────────────────────────────────
        entities, ner_ok = self._run_ner(text)

        # 2) Summarisation ───────────────────────────────────────────────
        summary, sum_ok = self._run_summary(text)

        # 3) Zero-shot classification ────────────────────────────────
        categories, clf_ok = self._run_classification(text)

        # 4) Keyword scan (fast, always runs) ──────────────────────────
        critical_kws, high_kws, medium_kws = self._scan_keywords(text)

        # Track which sub-models ran successfully
        components_status = {
            "ner": "ok" if ner_ok else ("unavailable" if self.ner is None else "error"),
            "summarizer": "ok" if sum_ok else ("unavailable" if self.summarizer is None else "error"),
            "classifier": "ok" if clf_ok else ("unavailable" if self.classifier is None else "error"),
        }

        # 5) Derive top label + confidence + risk ──────────────────────
        if categories:
            top = categories[0]
            label = top["label"]
            confidence = top["score"]
        elif entities:
            label = "entities-detected"
            confidence = max(e["confidence"] for e in entities)
        else:
            label = "no-findings"
            confidence = 0.0

        risk_level = self._assess_risk(categories, entities, critical_kws, high_kws, medium_kws)

        return {
            "label": label,
            "confidence": round(confidence, 4),
            "tokens_processed": tokens_processed,
            "entities": entities,
            "summary": summary,
            "categories": categories,
            "risk_level": risk_level,
            "critical_keywords": critical_kws,
            "high_keywords": high_kws,
            "medium_keywords": medium_kws,
            "components_status": components_status,
        }

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #
    def _run_ner(self, text: str) -> tuple[list[dict], bool]:
        if self.ner is None:
            return [], False
        try:
            # BERT-base-NER has a 512 token window; truncate gracefully
            raw = self.ner(text[:10_000])
            entities = [
                {
                    "text": ent["word"],
                    "entity_type": ent["entity_group"],
                    "start": ent["start"],
                    "end": ent["end"],
                    "confidence": round(float(ent["score"]), 4),
                }
                for ent in raw
            ]
            return entities, True
        except Exception as exc:
            logger.error("NER inference error: %s", exc)
            return [], False

    def _run_summary(self, text: str) -> tuple[str, bool]:
        if self.summarizer is None:
            return "", False
        try:
            import torch

            words = text.split()
            if len(words) < 40:
                return text.strip(), True

            # Chunk if necessary (model limit ~1024 tokens)
            chunk = " ".join(words[:1024])
            inputs = self._sum_tokenizer(
                chunk, return_tensors="pt", max_length=1024, truncation=True
            )
            with torch.no_grad():
                summary_ids = self._sum_model.generate(
                    inputs["input_ids"],
                    max_length=200,
                    min_length=30,
                    do_sample=False,
                    num_beams=4,
                )
            return self._sum_tokenizer.decode(summary_ids[0], skip_special_tokens=True), True
        except Exception as exc:
            logger.error("Summarisation error: %s", exc)
            return "", False

    def _run_classification(self, text: str) -> tuple[list[dict], bool]:
        if self.classifier is None:
            return [], False
        try:
            # Use first 512 words for speed
            snippet = " ".join(text.split()[:512])
            result = self.classifier(
                snippet, candidate_labels=THREAT_CATEGORIES, multi_label=True
            )
            categories = [
                {"label": lbl, "score": round(float(sc), 4)}
                for lbl, sc in zip(result["labels"], result["scores"])
                if sc > 0.06  # lower threshold — 12 labels means more score spread
            ]
            return categories, True
        except Exception as exc:
            logger.error("Classification error: %s", exc)
            return [], False

    @staticmethod
    def _scan_keywords(text: str) -> tuple[list[str], list[str], list[str]]:
        """Fast keyword scan independent of HuggingFace models."""
        t = text.lower()
        critical = sorted({kw for kw in _KW_CRITICAL if kw in t})
        high = sorted({kw for kw in _KW_HIGH if kw in t})
        medium = sorted({kw for kw in _KW_MEDIUM if kw in t})
        return critical, high, medium

    @staticmethod
    def _assess_risk(
        categories: list[dict],
        entities: list[dict],
        critical_kws: list[str],
        high_kws: list[str],
        medium_kws: list[str],
    ) -> str:
        # Keyword evidence always wins
        if critical_kws:
            return "HIGH"
        if len(high_kws) >= 2:
            return "HIGH"
        if high_kws:
            return "HIGH"

        # Zero-shot classifier signal (lower threshold than before)
        for cat in categories:
            if cat["label"] in _HIGH_LABELS and cat["score"] > 0.25:
                return "HIGH"
        for cat in categories:
            if cat["label"] in _MEDIUM_LABELS and cat["score"] > 0.25:
                return "MEDIUM"

        # Medium keywords as fallback
        if len(medium_kws) >= 3:
            return "MEDIUM"
        if medium_kws:
            return "MEDIUM"

        # NER entities as weak signal
        sensitive_types = {"PER", "ORG", "MISC"}
        if sum(1 for e in entities if e["entity_type"] in sensitive_types) >= 5:
            return "MEDIUM"

        return "LOW"
