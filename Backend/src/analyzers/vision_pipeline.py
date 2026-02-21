"""
Vision Pipeline Module
YOLOv8 object detection for forensic image analysis.
"""

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import torch
import torch.nn as nn
from PIL import Image
from ultralytics import YOLO

from .interface import AnalyzerInterface

logger = logging.getLogger("SENTINEL_VISION")

HIGH_RISK_CLASSES = frozenset({
    "knife",
    "scissors",
    "gun",
})

MEDIUM_RISK_CLASSES = frozenset({
    "person",
    "car",
    "truck",
    "bus",
    "motorcycle",
    "bicycle",
    "cell phone",
    "laptop",
    "tv",
    "backpack",
    "handbag",
    "suitcase",
})


class VisionPipeline(AnalyzerInterface):
    """Vision analyzer using YOLOv8 and optional violence detection."""

    PIPELINE_NAME = "vision_pipeline"

    def __init__(self, db=None, model_path: Optional[str] = None, violence_model_path: Optional[str] = None):
        try:
            from config import (
                GPU_ID,
                PROJECT_ROOT,
                YOLO_CONFIDENCE,
                YOLO_IMG_SIZE,
                YOLO_IOU,
                YOLO_MAX_DETECTIONS,
                YOLO_MODEL_PATH,
            )
        except Exception:
            from src.config import (  # type: ignore
                GPU_ID,
                PROJECT_ROOT,
                YOLO_CONFIDENCE,
                YOLO_IMG_SIZE,
                YOLO_IOU,
                YOLO_MAX_DETECTIONS,
                YOLO_MODEL_PATH,
            )

        self.db = db
        self.model_path = model_path or YOLO_MODEL_PATH
        self.violence_model_path = violence_model_path or os.path.join(
            PROJECT_ROOT, "MODELS", "Image", "best_violence_model.pth"
        )
        self.confidence = YOLO_CONFIDENCE
        self.iou = YOLO_IOU
        self.img_size = YOLO_IMG_SIZE
        self.max_det = YOLO_MAX_DETECTIONS
        self.gpu_id = GPU_ID

        self.device: str = "cpu"
        self.model: Optional[YOLO] = None
        self.violence_model: Optional[nn.Module] = None
        self.violence_ready = False

    def validate(self) -> bool:
        try:
            if torch.cuda.is_available():
                self.device = f"cuda:{self.gpu_id}"
                logger.info("GPU detected - using %s", self.device)
            else:
                self.device = "cpu"
                logger.warning("No GPU detected - using CPU inference.")
        except Exception:
            self.device = "cpu"

        if not os.path.isfile(self.model_path):
            raise FileNotFoundError(f"YOLO model weights not found at: {self.model_path}")

        supported_formats = (".pt", ".onnx", ".tflite", ".pb", ".mlmodel", ".torchscript")
        if self.model_path.lower().endswith(supported_formats):
            try:
                self.model = YOLO(self.model_path)
                logger.info("YOLO model loaded from %s", self.model_path)
            except Exception as exc:
                logger.warning("Failed to load YOLO model from %s: %s", self.model_path, exc)
        else:
            logger.warning("Unsupported YOLO format: %s", self.model_path)

        try:
            if os.path.exists(self.violence_model_path):
                self._load_violence_model()
            else:
                logger.warning("Violence model not found at %s", self.violence_model_path)
        except Exception as exc:
            logger.warning("Failed to load violence model: %s", exc)

        return True

    def _load_violence_model(self) -> None:
        try:
            self.violence_model = torch.load(self.violence_model_path, map_location=self.device)
            if hasattr(self.violence_model, "eval"):
                self.violence_model.eval()
            self.violence_ready = True
            logger.info("Violence model loaded from %s", self.violence_model_path)
        except Exception as exc:
            logger.error("Failed to load violence model: %s", exc)
            self.violence_ready = False

    def analyze(self, image_path: str) -> Dict[str, Any]:
        start = time.perf_counter()
        detections: List[Dict[str, Any]] = []

        if self.model is not None:
            try:
                results = self.model.predict(
                    source=image_path,
                    conf=self.confidence,
                    iou=self.iou,
                    imgsz=self.img_size,
                    max_det=self.max_det,
                    device=self.device,
                    verbose=False,
                )
                detections = self._parse_results(results[0])
            except Exception as exc:
                logger.warning("YOLO inference failed for %s: %s", image_path, exc)

        elapsed_ms = (time.perf_counter() - start) * 1000

        violence_score = 0.0
        violence_detected = False
        if self.violence_ready:
            try:
                violence_score, violence_detected = self._detect_violence(image_path)
            except Exception as exc:
                logger.warning("Violence detection failed: %s", exc)

        risk_level = self._classify_risk(detections, violence_detected)
        return {
            "detections": detections,
            "detection_count": len(detections),
            "violence_score": round(violence_score, 4),
            "violence_detected": violence_detected,
            "risk_level": risk_level,
            "inference_time_ms": round(elapsed_ms, 2),
        }

    def run(self) -> int:
        self.validate()

        if self.db is None:
            logger.warning("No database handler, skipping vision pipeline.")
            return 0

        image_files = self.db.get_files_by_mime("image/%")
        total = len(image_files)
        if total == 0:
            logger.info("No pending image files found - skipping vision pipeline.")
            return 0

        processed = 0
        for file_id, file_path, _ in image_files:
            try:
                if not os.path.isfile(file_path):
                    self.db.update_file_status(file_id, "ERROR")
                    continue

                result = self.analyze(file_path)
                self.db.insert_artifact(
                    file_id=file_id,
                    pipeline_name=self.PIPELINE_NAME,
                    risk_level=result["risk_level"],
                    description=self._build_description(file_path, result),
                    metadata=json.dumps(result, default=str),
                )
                self.db.update_file_status(file_id, "PROCESSED")
                processed += 1
            except Exception:
                logger.exception("Error processing %s", file_path)
                self.db.update_file_status(file_id, "ERROR")

        logger.info("Vision pipeline complete. %d/%d images processed.", processed, total)
        return processed

    @staticmethod
    def _parse_results(result) -> List[Dict[str, Any]]:
        detections: List[Dict[str, Any]] = []
        boxes = result.boxes
        if boxes is None or len(boxes) == 0:
            return detections

        names = result.names
        for box in boxes:
            class_id = int(box.cls.item())
            detections.append({
                "class_name": names.get(class_id, f"class_{class_id}"),
                "confidence": round(float(box.conf.item()), 4),
                "bbox": [round(float(c), 2) for c in box.xyxy[0].tolist()],
            })
        detections.sort(key=lambda item: item["confidence"], reverse=True)
        return detections

    @staticmethod
    def _classify_risk(detections: List[Dict[str, Any]], violence_detected: bool = False) -> str:
        if violence_detected:
            return "HIGH"
        detected_classes = {item["class_name"] for item in detections}
        if detected_classes & HIGH_RISK_CLASSES:
            return "HIGH"
        if detected_classes & MEDIUM_RISK_CLASSES:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _build_description(file_path: str, result: Dict[str, Any]) -> str:
        count = result["detection_count"]
        risk = result["risk_level"]
        filename = os.path.basename(file_path)

        if count == 0 and not result.get("violence_detected", False):
            return f"No objects detected in {filename}."

        class_summary: Dict[str, int] = {}
        for item in result["detections"]:
            class_summary[item["class_name"]] = class_summary.get(item["class_name"], 0) + 1
        parts = [f"{amount}x {name}" for name, amount in class_summary.items()]

        if result.get("violence_detected", False):
            violence_note = f" + VIOLENCE DETECTED (score: {result.get('violence_score', 0):.2f})"
        else:
            violence_note = ""

        if count == 0:
            return f"[{risk}] {filename}: Violence detected{violence_note}"
        return f"[{risk}] {filename}: {count} detection(s) - {', '.join(parts)}{violence_note}"

    def _detect_violence(self, image_path: str) -> Tuple[float, bool]:
        if not self.violence_ready or self.violence_model is None:
            return 0.0, False

        try:
            image = Image.open(image_path).convert("RGB")
            image = image.resize((224, 224))
            image_array = np.array(image, dtype=np.float32) / 255.0

            if image_array.ndim == 3 and image_array.shape[2] == 3:
                image_array = np.transpose(image_array, (2, 0, 1))

            image_tensor = torch.from_numpy(image_array).unsqueeze(0).to(self.device)
            with torch.no_grad():
                output = self.violence_model(image_tensor)

            if isinstance(output, torch.Tensor):
                if output.ndim > 1 and output.shape[1] == 2:
                    violence_prob = torch.softmax(output, dim=1)[0, 1].item()
                else:
                    violence_prob = torch.sigmoid(output.flatten()[0]).item()
                return float(violence_prob), bool(violence_prob > 0.5)
        except Exception as exc:
            logger.debug("Violence inference failed: %s", exc)

        return 0.0, False
