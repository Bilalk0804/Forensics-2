"""Text analysis service — delegates to TextModel."""
import asyncio
import logging
from api.services.model_registry import ModelRegistry

logger = logging.getLogger(__name__)


async def run_text_analysis(text: str) -> dict:
    """
    Run NLP analysis on raw text.

    Returns a dict matching TextAnalyzeResponse schema:
        label, confidence, tokens_processed, entities, summary, categories, risk_level
    """
    model = ModelRegistry.get("text")
    result = await asyncio.to_thread(model.predict, text)
    return result
