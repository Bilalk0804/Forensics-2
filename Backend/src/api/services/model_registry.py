"""Central model registry - loads all models once at startup."""
import asyncio
import logging
import os
from typing import Any

# Force all HuggingFace models to use PyTorch (avoids Keras 3 / TF conflict)
os.environ["USE_TORCH"] = "1"
os.environ["TRANSFORMERS_NO_TF"] = "1"

logger = logging.getLogger(__name__)


class ModelRegistry:
    """
    Central registry for all forensic ML models.
    Models are loaded once at startup and shared across requests.
    """
    _registry: dict[str, Any] = {}

    @classmethod
    async def load_all(cls) -> None:
        """Load all forensic analysis models at startup."""
        model_loaders = {
            "text": ("api.models.text_model", "TextModel"),
            "vision": ("api.models.vision_model", "VisionModel"),
            "malware": ("api.models.malware_model", "MalwareModel"),
            "file": ("api.models.file_model", "FileModel"),
            "audio": ("api.models.audio_model", "AudioModel"),
            "deepfake": ("api.models.deepfake_model", "DeepfakeModel"),
        }

        for key, (module_path, class_name) in model_loaders.items():
            try:
                module = __import__(module_path, fromlist=[class_name])
                model_class = getattr(module, class_name)
                cls._registry[key] = await asyncio.to_thread(model_class)
                logger.info(f"✓ {key} model loaded")
            except ImportError as e:
                logger.warning(f"✗ {key} model import failed: {e}")
                cls._registry[key] = None
            except Exception as e:
                logger.error(f"✗ {key} model initialization failed: {e}")
                cls._registry[key] = None

    @classmethod
    async def unload_all(cls) -> None:
        """Unload all models at shutdown."""
        cls._registry.clear()
        logger.info("All models unloaded")

    @classmethod
    def get(cls, key: str) -> Any:
        """Get a model from registry."""
        model = cls._registry.get(key)
        if model is None:
            raise RuntimeError(f"Model '{key}' is not available.")
        return model

    @classmethod
    def loaded_models(cls) -> list[str]:
        """Return list of successfully loaded models."""
        return [k for k, v in cls._registry.items() if v is not None]
