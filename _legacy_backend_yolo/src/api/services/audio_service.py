"""Audio analysis service."""
import asyncio
import logging
from api.services.model_registry import ModelRegistry

logger = logging.getLogger(__name__)


async def run_audio_analysis(data: bytes, filename: str) -> dict:
    """
    Run audio analysis asynchronously.
    
    Args:
        data: Audio file bytes
        filename: Original filename
        
    Returns:
        Analysis results dictionary
    """
    model = ModelRegistry.get("audio")
    
    def _infer():
        return model.predict(data)
    
    result = await asyncio.to_thread(_infer)
    result.setdefault("filename", filename)
    result.setdefault("size_bytes", len(data))
    return result
