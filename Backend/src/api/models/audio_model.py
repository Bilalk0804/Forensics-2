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
            }

        try:
            duration = self._estimate_duration(data)
            transcription = self._transcribe(data)

            has_content = len(transcription.strip()) > 0
            return {
                "label": "speech-detected" if has_content else "no-speech",
                "confidence": 0.85 if has_content else 0.5,
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
            }

    # ------------------------------------------------------------------ #
    def _transcribe(self, data: bytes) -> str:
        """Run Whisper on audio bytes."""
        try:
            # Write to temp file for librosa / Whisper to read
            with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as tmp:
                tmp.write(data)
                tmp_path = tmp.name

            result = self.pipeline(tmp_path)
            os.unlink(tmp_path)
            return result.get("text", "")
        except Exception as exc:
            logger.error("Transcription error: %s", exc)
            return ""

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
