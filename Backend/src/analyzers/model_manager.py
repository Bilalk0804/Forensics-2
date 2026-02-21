"""
Model Manager Module
Manages initialization, loading, and lifecycle of forensic analysis models.
Handles GPU memory optimization and model caching.
"""

import os
import logging
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
import psutil
try:
    import GPUtil
except ImportError:
    GPUtil = None

logger = logging.getLogger("SENTINEL_MODEL_MANAGER")


class ModelManager:
    """Manages all forensic analysis models with GPU memory optimization."""

    def __init__(self, gpu_id: int = 0, vram_limit: float = 0.9):
        """
        Initialize Model Manager.
        
        Args:
            gpu_id: GPU device ID to use
            vram_limit: Maximum VRAM utilization (0-1)
        """
        self.gpu_id = gpu_id
        self.vram_limit = vram_limit
        self.models = {}
        self.model_registry = {}
        self.is_gpu_available = self._check_gpu_availability()
        self._register_models()
        logger.info(f"ModelManager initialized - GPU Available: {self.is_gpu_available}")

    def _check_gpu_availability(self) -> bool:
        """Check GPU availability and VRAM."""
        try:
            import torch
            if not torch.cuda.is_available():
                logger.warning("CUDA not available, will use CPU")
                return False
            
            vram = torch.cuda.get_device_properties(self.gpu_id).total_memory / 1e9
            logger.info(f"GPU {self.gpu_id}: {vram:.2f}GB VRAM available")
            return True
        except Exception as e:
            logger.warning(f"GPU check failed: {e}, will use CPU")
            return False

    def _register_models(self):
        """Register all available models and their metadata."""
        self.model_registry = {
            # Vision Models
            "yolo_v8": {
                "type": "vision",
                "path": "yolov8n.pt",
                "framework": "ultralytics",
                "vram_required": 0.2,
                "purpose": "object_detection",
                "description": "YOLOv8 Nano for fast object detection"
            },
            "lstm_deepfake": {
                "type": "vision",
                "path": "../MODELS/vision/best_lstm_model_final.keras",
                "framework": "tensorflow",
                "vram_required": 0.3,
                "purpose": "deepfake_detection",
                "description": "LSTM-based deepfake detection model"
            },
            "efficientnet": {
                "type": "vision",
                "path": "efficientnet_b0",
                "framework": "torchvision",
                "vram_required": 0.15,
                "purpose": "image_classification",
                "description": "EfficientNet for general image classification"
            },
            
            # Text Models
            "roberta_toxicity": {
                "type": "text",
                "path": "roberta-base",
                "framework": "huggingface",
                "vram_required": 0.25,
                "purpose": "content_analysis",
                "description": "RoBERTa for text analysis and threat detection"
            },
            "bert_ner": {
                "type": "text",
                "path": "bert-base-cased",
                "framework": "huggingface",
                "vram_required": 0.2,
                "purpose": "entity_extraction",
                "description": "BERT for Named Entity Recognition"
            },
            "distilbert_classification": {
                "type": "text",
                "path": "distilbert-base-uncased",
                "framework": "huggingface",
                "vram_required": 0.1,
                "purpose": "text_classification",
                "description": "DistilBERT for fast text classification"
            },
            
            # Audio Models
            "wav2vec_speech": {
                "type": "audio",
                "path": "facebook/wav2vec2-base-960h",
                "framework": "huggingface",
                "vram_required": 0.4,
                "purpose": "speech_recognition",
                "description": "Wav2Vec2 for speech-to-text"
            },
            
            # Multimodal Models
            "clip_vision_text": {
                "type": "multimodal",
                "path": "openai/clip-vit-base-patch32",
                "framework": "huggingface",
                "vram_required": 0.35,
                "purpose": "multimodal_analysis",
                "description": "CLIP for vision-text relationship analysis"
            },
            
            # Metadata & Binary Analysis
            "tabnet_metadata": {
                "type": "metadata",
                "path": "tabnet_metadata.pkl",
                "framework": "sklearn",
                "vram_required": 0.05,
                "purpose": "metadata_anomaly_detection",
                "description": "TabNet for metadata anomaly detection"
            },
            
            # LLM Models (Local)
            "llama_forensics": {
                "type": "llm",
                "path": "ggml-model-q4_k_m.gguf",
                "framework": "llama-cpp-python",
                "vram_required": 0.5,
                "purpose": "forensic_analysis",
                "description": "Local LLaMA model for forensic analysis"
            }
        }

    def get_model_registry(self) -> Dict[str, Dict[str, Any]]:
        """Get all registered models."""
        return self.model_registry

    def load_model(self, model_name: str, force_cpu: bool = False) -> Optional[Any]:
        """
        Load a model into memory.
        
        Args:
            model_name: Name of model to load
            force_cpu: Force CPU loading even if GPU available
            
        Returns:
            Loaded model or None if failed
        """
        if model_name in self.models:
            logger.info(f"Model {model_name} already loaded, returning cached")
            return self.models[model_name]

        if model_name not in self.model_registry:
            logger.error(f"Model {model_name} not in registry")
            return None

        model_info = self.model_registry[model_name]
        
        # Check VRAM availability
        if not force_cpu and self.is_gpu_available:
            if not self._check_vram_available(model_info["vram_required"]):
                logger.warning(f"Insufficient VRAM for {model_name}, clearing cache")
                self._clear_model_cache()

        try:
            logger.info(f"Loading model: {model_name} ({model_info['framework']})")
            
            device = "cpu" if force_cpu or not self.is_gpu_available else f"cuda:{self.gpu_id}"
            
            model = self._load_by_framework(
                model_info["framework"],
                model_info["path"],
                model_info["purpose"],
                device
            )
            
            if model is not None:
                self.models[model_name] = model
                logger.info(f"Successfully loaded {model_name}")
                return model
                
        except Exception as e:
            logger.error(f"Failed to load {model_name}: {e}")
            return None

    def _load_by_framework(
        self,
        framework: str,
        model_path: str,
        purpose: str,
        device: str
    ) -> Optional[Any]:
        """Load model based on its framework."""
        
        try:
            if framework == "ultralytics":
                from ultralytics import YOLO
                model = YOLO(model_path)
                return model
            
            elif framework == "tensorflow":
                import tensorflow as tf
                model = tf.keras.models.load_model(model_path)
                return model
            
            elif framework == "torchvision":
                import torch
                import torchvision.models as models
                model_name = model_path.split("_")[0].lower()
                model = getattr(models, model_name)(pretrained=True)
                model = model.to(device)
                return model
            
            elif framework == "huggingface":
                from transformers import AutoModel, AutoTokenizer
                
                # Load based on purpose
                if purpose == "toxicity" or "entity" in purpose:
                    tokenizer = AutoTokenizer.from_pretrained(model_path)
                    model = AutoModel.from_pretrained(model_path)
                else:
                    from transformers import AutoModelForSequenceClassification
                    model = AutoModelForSequenceClassification.from_pretrained(model_path)
                    
                model = model.to(device)
                return model
            
            elif framework == "llama-cpp-python":
                from llama_cpp import Llama
                model_full_path = self._find_model_path(model_path)
                model = Llama(
                    model_path=model_full_path,
                    n_gpu_layers=40 if device != "cpu" else 0,
                    n_ctx=2048
                )
                return model
            
            elif framework == "sklearn":
                import pickle
                model_full_path = self._find_model_path(model_path)
                with open(model_full_path, 'rb') as f:
                    model = pickle.load(f)
                return model
                
        except Exception as e:
            logger.error(f"Framework {framework} loading failed: {e}")
            return None

    def _find_model_path(self, model_path: str) -> str:
        """Find full path to model file."""
        base_paths = [
            Path("../MODELS"),
            Path("./MODELS"),
            Path(model_path)
        ]
        
        for base in base_paths:
            full_path = base / model_path if not Path(model_path).is_absolute() else Path(model_path)
            if full_path.exists():
                return str(full_path)
        
        return model_path  # Return as-is if not found, let loader handle it

    def _check_vram_available(self, required_gb: float) -> bool:
        """Check if sufficient VRAM is available."""
        try:
            import torch
            if not self.is_gpu_available:
                return False
            
            free_vram = torch.cuda.get_device_properties(self.gpu_id).total_memory
            free_vram = torch.cuda.mem_get_info(self.gpu_id)[0] / 1e9  # Convert to GB
            
            return free_vram > required_gb
        except Exception as e:
            logger.warning(f"Could not check VRAM: {e}")
            return False

    def _clear_model_cache(self):
        """Clear cached models to free memory."""
        try:
            import torch
            for name in list(self.models.keys()):
                del self.models[name]
            
            if self.is_gpu_available:
                torch.cuda.empty_cache()
            logger.info("Model cache cleared")
        except Exception as e:
            logger.warning(f"Cache clearing failed: {e}")

    def unload_model(self, model_name: str):
        """Unload a specific model."""
        if model_name in self.models:
            del self.models[model_name]
            logger.info(f"Unloaded {model_name}")

    def get_models_by_type(self, model_type: str) -> Dict[str, Any]:
        """Get all models of a specific type."""
        return {
            name: info for name, info in self.model_registry.items()
            if info["type"] == model_type
        }

    def get_system_info(self) -> Dict[str, Any]:
        """Get system and GPU information."""
        info = {
            "cpu_count": os.cpu_count(),
            "cpu_percent": psutil.cpu_percent(interval=1),
            "ram_available_gb": psutil.virtual_memory().available / 1e9,
            "gpu_available": self.is_gpu_available
        }
        
        try:
            if GPUtil is not None:
                gpus = GPUtil.getGPUs()
                if gpus:
                    gpu = gpus[self.gpu_id]
                    info["gpu_name"] = gpu.name
                    info["gpu_memory_free_mb"] = gpu.memoryFree
                    info["gpu_memory_used_mb"] = gpu.memoryUsed
                    info["gpu_load"] = gpu.load
        except Exception as e:
            logger.warning(f"Could not get GPU info: {e}")
        
        return info
