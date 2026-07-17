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

    When USE_REMOTE_INFERENCE=true and KAGGLE_INFERENCE_URL is set, the four
    heavy GPU models (text, vision, audio, deepfake) are replaced with lightweight
    HTTP wrappers that call a Kaggle GPU notebook via ngrok.  File and malware
    models always run locally (no HuggingFace, already fast).
    """
    _registry: dict[str, Any] = {}

    @classmethod
    async def load_all(cls) -> None:
        """Load all forensic analysis models at startup."""
        from src import config  # local import avoids circular imports at module level

        if config.USE_REMOTE_INFERENCE and config.KAGGLE_INFERENCE_URL:
            logger.info("Remote inference mode — connecting to Kaggle GPU at %s", config.KAGGLE_INFERENCE_URL)
            await cls._load_remote(config.KAGGLE_INFERENCE_URL)
        else:
            if config.USE_REMOTE_INFERENCE:
                logger.warning("USE_REMOTE_INFERENCE=true but KAGGLE_INFERENCE_URL is empty — falling back to local")
            await cls._load_local()

    # ------------------------------------------------------------------
    @classmethod
    async def _load_remote(cls, base_url: str) -> None:
        """Register remote HTTP wrappers for GPU models; load local lightweight models."""
        from api.models.remote_models import (
            RemoteTextModel, RemoteAudioModel, RemoteVisionModel, RemoteDeepfakeModel
        )

        # Remote GPU models — instantiated immediately (no heavy download)
        cls._registry["text"]     = RemoteTextModel(base_url)
        cls._registry["audio"]    = RemoteAudioModel(base_url)
        cls._registry["vision"]   = RemoteVisionModel(base_url)
        cls._registry["deepfake"] = RemoteDeepfakeModel(base_url)
        logger.info("✓ Remote models registered (text, audio, vision, deepfake)")

        # Local lightweight models — still run on this machine
        local_loaders = {
            "malware": ("api.models.malware_model", "MalwareModel"),
            "file":    ("api.models.file_model",    "FileModel"),
        }
        for key, (module_path, class_name) in local_loaders.items():
            try:
                module = __import__(module_path, fromlist=[class_name])
                model_class = getattr(module, class_name)
                cls._registry[key] = await asyncio.to_thread(model_class)
                logger.info(f"✓ {key} model loaded (local)")
            except Exception as e:
                logger.error(f"✗ {key} model initialization failed: {e}")
                cls._registry[key] = None

    # ------------------------------------------------------------------
    @classmethod
    async def _load_local(cls) -> None:
        """Original behaviour — load all six models locally."""
        model_loaders = {
            "text":     ("api.models.text_model",     "TextModel"),
            "vision":   ("api.models.vision_model",   "VisionModel"),
            "malware":  ("api.models.malware_model",  "MalwareModel"),
            "file":     ("api.models.file_model",     "FileModel"),
            "audio":    ("api.models.audio_model",    "AudioModel"),
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
