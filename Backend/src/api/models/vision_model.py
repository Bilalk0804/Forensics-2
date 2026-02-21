"""
Vision / Image analysis model — Direct HuggingFace + YOLO inference.

Models loaded:
  - Object detection:    YOLOv8n  (ultralytics, already in repo)
  - Violence detection:  jaranohaal/vit-base-violence-detection  (HuggingFace ViT)
"""

import io
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Objects considered forensically significant
HIGH_RISK_OBJECTS = {"knife", "scissors", "gun", "rifle", "pistol", "sword"}
MEDIUM_RISK_OBJECTS = {"person", "car", "truck", "motorcycle", "bus", "cell phone", "laptop", "backpack", "suitcase"}

# Violence detection threshold.
# The ViT model returns ~0.50-0.56 on normal face/portrait images (essentially
# random noise). Require ≥0.70 to declare violence, eliminating false positives
# from face close-ups, emotional expressions, etc.
_VIOLENCE_THRESHOLD = 0.70


class VisionModel:
    """Loads YOLO + ViT violence detector at init and exposes .predict()."""

    def __init__(self):
        import torch

        self.device = "cuda:0" if torch.cuda.is_available() else "cpu"
        self.yolo = None
        self.violence_model = None
        self.violence_extractor = None

        # ── YOLO object detection ─────────────────────────────
        try:
            from ultralytics import YOLO

            weights = Path(__file__).resolve().parents[3] / "yolov8n.pt"
            if not weights.exists():
                weights = "yolov8n.pt"  # auto-download
            self.yolo = YOLO(str(weights))
            logger.info("✓ YOLO model loaded (%s)", weights)
        except Exception as exc:
            logger.warning("✗ YOLO load failed: %s", exc)

        # ── ViT violence classifier ────────────────────────────
        try:
            from transformers import ViTForImageClassification, ViTImageProcessor

            model_name = "jaranohaal/vit-base-violence-detection"
            self.violence_model = ViTForImageClassification.from_pretrained(model_name)
            # preprocessor_config.json for this checkpoint lacks `image_processor_type`,
            # so AutoImageProcessor cannot resolve it. Use ViTImageProcessor directly
            # with the standard ViT-Base preprocessing parameters (224×224, mean/std=0.5).
            self.violence_extractor = ViTImageProcessor(
                size={"height": 224, "width": 224},
                image_mean=[0.5, 0.5, 0.5],
                image_std=[0.5, 0.5, 0.5],
            )
            self.violence_model.eval()
            logger.info("✓ ViT violence model loaded")
        except Exception as exc:
            logger.warning("✗ ViT violence model failed: %s", exc)

    # ------------------------------------------------------------------ #
    def predict(self, data: bytes) -> dict:
        """
        Analyse an image from raw bytes.

        Returns dict with:
            label, confidence, detections[], violence_detected, violence_score
        """
        from PIL import Image

        image = Image.open(io.BytesIO(data)).convert("RGB")

        detections = self._run_yolo(image)
        violence_detected, violence_score = self._run_violence(image)

        risk = self._classify_risk(detections, violence_detected, violence_score)

        if violence_detected:
            label = "violence-detected"
            confidence = violence_score
        elif detections:
            label = detections[0]["class_name"]
            confidence = detections[0]["confidence"]
        else:
            label = "no-objects"
            confidence = 1.0

        # Build human-readable summary
        summary_parts = []
        if detections:
            obj_counts: dict[str, int] = {}
            for d in detections:
                n = d["class_name"]
                obj_counts[n] = obj_counts.get(n, 0) + 1
            obj_strs = [f"{cnt} {name}" if cnt > 1 else name for name, cnt in obj_counts.items()]
            summary_parts.append(f"Detected {', '.join(obj_strs)}.")
        if violence_detected:
            summary_parts.append(f"Violence detected (score {violence_score:.2f}).")
        summary = " ".join(summary_parts) if summary_parts else "No significant objects or violence detected."

        return {
            "label": label,
            "confidence": round(confidence, 4),
            "detections": detections,
            "violence_detected": violence_detected,
            "violence_score": round(violence_score, 4),
            "risk_level": risk,
            "detection_count": len(detections),
            "summary": summary,
        }

    # ------------------------------------------------------------------ #
    def _run_yolo(self, image) -> list[dict]:
        if self.yolo is None:
            logger.warning("YOLO model not loaded — skipping object detection")
            return []
        try:
            results = self.yolo.predict(
                source=image, conf=0.25, imgsz=640, device="cpu", verbose=False
            )
            result = results[0]
            boxes = result.boxes
            if boxes is None or len(boxes) == 0:
                return []

            names = result.names
            dets = []
            for box in boxes:
                cls_id = int(box.cls.item())
                conf = float(box.conf.item())
                bbox = box.xyxy[0].tolist()
                dets.append({
                    "class_name": names.get(cls_id, str(cls_id)),
                    "confidence": round(conf, 4),
                    "bbox": [round(v, 1) for v in bbox],
                })
            return dets
        except Exception as exc:
            logger.error("YOLO inference error: %s", exc)
            return []

    def _run_violence(self, image) -> tuple[bool, float]:
        if self.violence_model is None or self.violence_extractor is None:
            logger.warning("Violence detection model not loaded — skipping")
            return False, 0.0
        try:
            import torch

            inputs = self.violence_extractor(images=image, return_tensors="pt")
            with torch.no_grad():
                outputs = self.violence_model(**inputs)
                probs = torch.nn.functional.softmax(outputs.logits, dim=1).squeeze()

            id2label = self.violence_model.config.id2label
            # Find the violence/non-violence labels
            violence_idx = None
            for idx, lbl in id2label.items():
                if "violence" in str(lbl).lower() and "non" not in str(lbl).lower():
                    violence_idx = int(idx)
                    break

            if violence_idx is not None:
                score = float(probs[violence_idx])
                return score > _VIOLENCE_THRESHOLD, score
            else:
                predicted = int(probs.argmax())
                score = float(probs[predicted])
                lbl = id2label.get(predicted, "")
                is_violence = "violence" in str(lbl).lower() and "non" not in str(lbl).lower()
                return is_violence and score > _VIOLENCE_THRESHOLD, score if is_violence else 1.0 - score
        except Exception as exc:
            logger.error("Violence detection error: %s", exc)
            return False, 0.0

    @staticmethod
    def _classify_risk(detections: list[dict], violence_detected: bool = False,
                       violence_score: float = 0.0) -> str:
        if violence_detected:
            # Tiered: very high confidence = HIGH, moderate confidence = MEDIUM
            return "HIGH" if violence_score >= 0.85 else "MEDIUM"
        for det in detections:
            if det["class_name"].lower() in HIGH_RISK_OBJECTS:
                return "HIGH"
        for det in detections:
            if det["class_name"].lower() in MEDIUM_RISK_OBJECTS:
                return "MEDIUM"
        return "LOW"
