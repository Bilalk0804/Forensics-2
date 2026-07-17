"""
Audio analysis model — HuggingFace Whisper for speech-to-text.

Model: openai/whisper-tiny (fast, ~150MB)
Transcribes audio and provides forensic metadata.
"""

import io
import logging
import tempfile
import os
from typing import Any

logger = logging.getLogger(__name__)


class AudioModel:
    """Loads Whisper at init for speech-to-text transcription."""

    def __init__(self):
        self.pipeline = None

        try:
            import torch
            from transformers import pipeline as hf_pipeline

            device = 0 if torch.cuda.is_available() else -1
            self.pipeline = hf_pipeline(
                "automatic-speech-recognition",
                model="openai/whisper-tiny",
                device=device,
            )
            logger.info("✓ Whisper model loaded (openai/whisper-tiny)")
        except Exception as exc:
            logger.warning("✗ Whisper model failed: %s", exc)

    # ------------------------------------------------------------------ #
    def predict(self, data: bytes) -> dict:
        """
        Transcribe audio from raw bytes.

        Returns dict with:
            label, confidence, transcription, duration_seconds
        """
        if self.pipeline is None:
            return {
                "label": "model-unavailable",
                "confidence": 0.0,
                "transcription": "",
                "duration_seconds": 0.0,
                "error": "Whisper model failed to load at startup. Check server logs.",
            }

        try:
            duration = self._estimate_duration(data)
            result = self._transcribe_with_confidence(data)
            transcription = result.get("text", "")
            # Use chunk-level confidence from Whisper when available
            raw_confidence = result.get("confidence", None)

            has_content = len(transcription.strip()) > 0

            if raw_confidence is not None:
                confidence = round(raw_confidence, 4)
            else:
                # Estimate confidence from transcription quality
                word_count = len(transcription.split())
                if not has_content:
                    confidence = 0.0
                elif word_count > 10:
                    confidence = 0.8
                else:
                    confidence = 0.5

            return {
                "label": "speech-detected" if has_content else "no-speech",
                "confidence": confidence,
                "transcription": transcription,
                "duration_seconds": round(duration, 2),
            }
        except Exception as exc:
            logger.error("Audio analysis error: %s", exc)
            return {
                "label": "error",
                "confidence": 0.0,
                "transcription": "",
                "duration_seconds": 0.0,
                "error": str(exc),
            }

    # ------------------------------------------------------------------ #
    def _transcribe_with_confidence(self, data: bytes) -> dict:
        """Run Whisper on audio bytes and return text + confidence."""
        try:
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
                tmp.write(data)
                tmp_path = tmp.name

            # Request chunk-level timestamps to extract confidence
            result = self.pipeline(tmp_path, return_timestamps=True)
            os.unlink(tmp_path)

            text = result.get("text", "")
            # Extract average chunk confidence when available
            chunks = result.get("chunks", [])
            if chunks:
                chunk_probs = [
                    c.get("confidence", c.get("avg_logprob", None))
                    for c in chunks
                    if c.get("confidence") is not None or c.get("avg_logprob") is not None
                ]
                if chunk_probs:
                    avg_conf = sum(chunk_probs) / len(chunk_probs)
                    # avg_logprob is negative; convert to 0-1 range
                    if avg_conf < 0:
                        import math
                        avg_conf = math.exp(avg_conf)
                    return {"text": text, "confidence": avg_conf}

            return {"text": text, "confidence": None}
        except Exception as exc:
            logger.error("Transcription error: %s", exc)
            return {"text": "", "confidence": None}

    def _transcribe(self, data: bytes) -> str:
        """Run Whisper on audio bytes (backward-compat)."""
        result = self._transcribe_with_confidence(data)
        return result.get("text", "")

    @staticmethod
    def _estimate_duration(data: bytes) -> float:
        """Estimate audio duration in seconds."""
        try:
            import librosa
            import soundfile as sf

            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
                tmp.write(data)
                tmp_path = tmp.name

            duration = librosa.get_duration(path=tmp_path)
            os.unlink(tmp_path)
            return float(duration)
        except Exception:
            # Rough estimate: assume 16-bit mono 16kHz WAV
            return len(data) / (16000 * 2)
