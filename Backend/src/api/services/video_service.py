"""Video/deepfake analysis service."""
import asyncio
import logging
from api.services.model_registry import ModelRegistry

logger = logging.getLogger(__name__)


async def run_deepfake_detection(data: bytes, filename: str) -> dict:
    """
    Run deepfake detection asynchronously.
    
    Args:
        data: Video file bytes
        filename: Original filename
        
    Returns:
        Detection results dictionary
    """
    model = ModelRegistry.get("deepfake")
    
    def _infer():
        return model.predict(data)
    
    result = await asyncio.to_thread(_infer)
    result.setdefault("filename", filename)
    result.setdefault("size_bytes", len(data))
    return result
