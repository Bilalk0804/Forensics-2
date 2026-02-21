"""Image classification service — delegates to VisionModel."""
import asyncio
import logging
from api.services.model_registry import ModelRegistry

logger = logging.getLogger(__name__)


async def run_image_classification(data: bytes, filename: str = "") -> dict:
    """
    Run image analysis (YOLO object detection + ViT violence detection).

    Returns a dict matching ImageClassifyResponse schema:
        label, confidence, detections, violence_detected, violence_score, risk_level
    """
    model = ModelRegistry.get("vision")
    result = await asyncio.to_thread(model.predict, data)
    result["filename"] = filename
    result["size_bytes"] = len(data)
    return result
