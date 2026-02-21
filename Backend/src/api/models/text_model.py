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

# Forensic threat categories used by the zero-shot classifier
THREAT_CATEGORIES = [
    "financial fraud",
    "violence or threats",
    "drug trafficking",
    "cyber crime",
    "identity theft",
    "exploitation",
    "corruption",
    "weapons",
    "general / benign",
]


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
        entities = self._run_ner(text)

        # 2) Summarisation ───────────────────────────────────────
        summary = self._run_summary(text)

        # 3) Zero-shot classification ────────────────────────────
        categories = self._run_classification(text)

        # 4) Derive top label + confidence + risk ────────────────
        if categories:
            top = categories[0]
            label = top["label"]
            confidence = top["score"]
        elif entities:
            label = "entities-detected"
            confidence = max(e["confidence"] for e in entities)
        else:
            label = "analyzed"
            confidence = 0.5

        risk_level = self._assess_risk(categories, entities)

        return {
            "label": label,
            "confidence": round(confidence, 4),
            "tokens_processed": tokens_processed,
            "entities": entities,
            "summary": summary,
            "categories": categories,
            "risk_level": risk_level,
        }

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #
    def _run_ner(self, text: str) -> list[dict]:
        if self.ner is None:
            return []
        try:
            # BERT-base-NER has a 512 token window; truncate gracefully
            raw = self.ner(text[:10_000])
            return [
                {
                    "text": ent["word"],
                    "entity_type": ent["entity_group"],
                    "start": ent["start"],
                    "end": ent["end"],
                    "confidence": round(float(ent["score"]), 4),
                }
                for ent in raw
            ]
        except Exception as exc:
            logger.error("NER inference error: %s", exc)
            return []

    def _run_summary(self, text: str) -> str:
        if self.summarizer is None:
            return ""
        try:
            import torch

            words = text.split()
            if len(words) < 40:
                return text.strip()

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
            return self._sum_tokenizer.decode(summary_ids[0], skip_special_tokens=True)
        except Exception as exc:
            logger.error("Summarisation error: %s", exc)
            return ""

    def _run_classification(self, text: str) -> list[dict]:
        if self.classifier is None:
            return []
        try:
            # Use first 512 words for speed
            snippet = " ".join(text.split()[:512])
            result = self.classifier(
                snippet, candidate_labels=THREAT_CATEGORIES, multi_label=True
            )
            return [
                {"label": lbl, "score": round(float(sc), 4)}
                for lbl, sc in zip(result["labels"], result["scores"])
                if sc > 0.10
            ]
        except Exception as exc:
            logger.error("Classification error: %s", exc)
            return []

    @staticmethod
    def _assess_risk(categories: list[dict], entities: list[dict]) -> str:
        high_risk_labels = {
            "violence or threats",
            "exploitation",
            "drug trafficking",
            "weapons",
        }
        medium_risk_labels = {
            "financial fraud",
            "cyber crime",
            "identity theft",
            "corruption",
        }

        for cat in categories:
            if cat["label"] in high_risk_labels and cat["score"] > 0.40:
                return "HIGH"
        for cat in categories:
            if cat["label"] in medium_risk_labels and cat["score"] > 0.40:
                return "MEDIUM"

        # Also check entity count as a secondary signal
        sensitive_types = {"PER", "ORG", "MISC"}
        sensitive_count = sum(
            1 for e in entities if e["entity_type"] in sensitive_types
        )
        if sensitive_count >= 5:
            return "MEDIUM"

        return "LOW"
