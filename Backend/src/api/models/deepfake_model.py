"""
Deepfake detection model — HuggingFace SigLIP classifier.

Model: prithivMLmods/deepfake-detector-model-v1
Extracts frames from video and classifies each as real/fake.
Also works on single images.
"""

import io
import logging
from typing import Any

logger = logging.getLogger(__name__)


class DeepfakeModel:
    """Loads a SigLIP-based deepfake classifier at init."""

    def __init__(self):
        import torch

        self.model = None
        self.processor = None
        self.device = "cuda:0" if torch.cuda.is_available() else "cpu"

        try:
            from transformers import AutoImageProcessor, SiglipForImageClassification

            model_name = "prithivMLmods/deepfake-detector-model-v1"
            self.model = SiglipForImageClassification.from_pretrained(model_name)
            self.processor = AutoImageProcessor.from_pretrained(model_name)
            self.model.eval()
            logger.info("✓ Deepfake detector loaded (%s)", model_name)
        except Exception as exc:
            logger.warning("✗ Deepfake model failed: %s", exc)

    # ------------------------------------------------------------------ #
    def predict(self, data: bytes) -> dict:
        """
        Detect deepfake in image/video bytes.

        For video: extracts up to 5 evenly-spaced frames and averages.
        For image: classifies directly.

        Returns dict with: is_deepfake, confidence, label
        """
        if self.model is None or self.processor is None:
            return {"is_deepfake": False, "confidence": 0.5, "label": "model-unavailable"}

        frames = self._extract_frames(data)
        if not frames:
            return {"is_deepfake": False, "confidence": 0.0, "label": "no-frames"}

        scores = []
        for frame in frames:
            score = self._classify_frame(frame)
            if score is not None:
                scores.append(score)

        if not scores:
            return {"is_deepfake": False, "confidence": 0.0, "label": "inference-error"}

        avg_fake_score = sum(scores) / len(scores)
        is_deepfake = avg_fake_score > 0.5

        return {
            "is_deepfake": is_deepfake,
            "confidence": round(avg_fake_score if is_deepfake else 1.0 - avg_fake_score, 4),
            "label": "fake" if is_deepfake else "real",
        }

    # ------------------------------------------------------------------ #
    def _classify_frame(self, image) -> float | None:
        """Return the 'fake' probability for a single PIL image."""
        try:
            import torch

            inputs = self.processor(images=image, return_tensors="pt")
            with torch.no_grad():
                outputs = self.model(**inputs)
                probs = torch.nn.functional.softmax(outputs.logits, dim=1).squeeze()

            # Find the "fake" class index
            id2label = self.model.config.id2label
            fake_idx = None
            for idx, lbl in id2label.items():
                if "fake" in str(lbl).lower():
                    fake_idx = int(idx)
                    break

            if fake_idx is not None:
                return float(probs[fake_idx])
            else:
                # Assume index 0 = fake if labels don't contain "fake"
                return float(probs[0])
        except Exception as exc:
            logger.error("Frame classification error: %s", exc)
            return None

    @staticmethod
    def _extract_frames(data: bytes, max_frames: int = 5) -> list:
        """
        Extract frames from video bytes, or return a single image.
        Falls back to treating data as an image if cv2 is unavailable.
        """
        from PIL import Image

        # Try as image first (most common path for the /api/video endpoint)
        try:
            img = Image.open(io.BytesIO(data)).convert("RGB")
            return [img]
        except Exception:
            pass

        # Try as video using OpenCV
        try:
            import cv2
            import tempfile
            import os
            import numpy as np

            with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tmp:
                tmp.write(data)
                tmp_path = tmp.name

            cap = cv2.VideoCapture(tmp_path)
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))

            if total_frames <= 0:
                cap.release()
                os.unlink(tmp_path)
                return []

            indices = [int(i * total_frames / max_frames) for i in range(max_frames)]
            frames = []
            for idx in indices:
                cap.set(cv2.CAP_PROP_POS_FRAMES, idx)
                ret, frame = cap.read()
                if ret:
                    rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    frames.append(Image.fromarray(rgb))

            cap.release()
            os.unlink(tmp_path)
            return frames
        except Exception as exc:
            logger.debug("Video frame extraction failed: %s", exc)
            return []
