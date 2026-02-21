"""
Configuration Module
Settings for GPU ID, VRAM limits, path constants, and model parameters.
"""

import os
from dotenv import load_dotenv
from pathlib import Path

# Load environment variables from .env file
load_dotenv()

# --- Base Paths ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = BASE_DIR  # alias

# Evidence & Output
EVIDENCE_PATH = os.path.join(PROJECT_ROOT, "EVIDENCE_LOCKER")
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "OUTPUT")
DB_PATH = os.path.join(OUTPUT_DIR, "forensics.db")
LOG_DIR = os.path.join(OUTPUT_DIR, "logs")
REPORT_DIR = os.path.join(OUTPUT_DIR, "reports")

# Backward-compatible aliases
LOGS_DIR = LOG_DIR
REPORTS_DIR = REPORT_DIR

# Model directories (support both legacy MODELS and lowercase models)
_MODEL_DIR_CANDIDATES = [
    os.path.join(PROJECT_ROOT, "models"),
    os.path.join(PROJECT_ROOT, "MODELS"),
]
MODELS_DIR = next((p for p in _MODEL_DIR_CANDIDATES if os.path.isdir(p)), _MODEL_DIR_CANDIDATES[0])
YARA_RULES_DIR = os.getenv("YARA_RULES_DIR", os.path.join(PROJECT_ROOT, "MODELS", "yara_rules"))
YARA_RULES_FILE = os.getenv("YARA_RULES_FILE", "")

# Auto-detect models
_model_paths = {}

def _auto_detect_models():
    """Auto-detect model files from models directory."""
    global _model_paths
    
    # YOLO model
    vision_dir = os.path.join(MODELS_DIR, "vision")
    yolo_candidates = [
        os.path.join(vision_dir, "best_lstm_model_final.keras"),
        os.path.join(vision_dir, "yolov8n.pt"),
        os.path.join(vision_dir, "Image", "best_lstm_model_final.keras"),
    ]
    
    for path in yolo_candidates:
        if os.path.exists(path):
            _model_paths['yolo'] = path
            break
    
    # Violence detection model
    vision_image_dir = os.path.join(MODELS_DIR, "vision", "Image")
    violence_path = os.path.join(vision_image_dir, "best_violence_model.pth")
    if os.path.exists(violence_path):
        _model_paths['violence'] = violence_path
    
    # Malware models
    malware_dir = os.path.join(MODELS_DIR, "malware_detection", "Malware-Detection-using-Machine-learning", "Classifier")
    
    malware_files = {
        'pe_classifier': os.path.join(malware_dir, "classifier.pkl"),
        'url_classifier': os.path.join(malware_dir, "pickel_model.pkl"),
        'url_vectorizer': os.path.join(malware_dir, "pickel_vector.pkl"),
    }
    
    for key, path in malware_files.items():
        if os.path.exists(path):
            _model_paths[key] = path
    
    return _model_paths

# Run auto-detection on module load
_auto_detect_models()

# --- Model Paths (with fallbacks) ---
YOLO_MODEL_PATH = _model_paths.get('yolo', os.path.join(MODELS_DIR, "vision", "best_lstm_model_final.keras"))
IMAGE_VIOLENCE_MODEL_PATH = _model_paths.get('violence', os.path.join(MODELS_DIR, "vision", "Image", "best_violence_model.pth"))
MALWARE_PE_CLASSIFIER = _model_paths.get('pe_classifier', os.path.join(MODELS_DIR, "malware_detection", "Malware-Detection-using-Machine-learning", "Classifier", "classifier.pkl"))
MALWARE_PE_FEATURES = os.path.join(MODELS_DIR, "malware_detection", "Malware-Detection-using-Machine-learning", "Classifier", "features.pkl")
MALWARE_URL_CLASSIFIER = _model_paths.get('url_classifier', os.path.join(MODELS_DIR, "malware_detection", "Malware-Detection-using-Machine-learning", "Classifier", "pickel_model.pkl"))
MALWARE_URL_VECTORIZER = _model_paths.get('url_vectorizer', os.path.join(MODELS_DIR, "malware_detection", "Malware-Detection-using-Machine-learning", "Classifier", "pickel_vector.pkl"))

# --- YOLO Configuration ---
YOLO_CONFIDENCE = 0.5
YOLO_IOU = 0.45
YOLO_IMG_SIZE = 640
YOLO_MAX_DETECTIONS = 300

# --- Image Analysis Configuration ---

# --- GPU Configuration ---
GPU_ID = 0
VRAM_LIMIT = 0.9  # 90% of available VRAM

# --- Docker Configuration ---
DOCKER_ENABLED = os.getenv("DOCKER_ENABLED", "false").lower() == "true"
DOCKER_MALWARE_IMAGE = os.getenv("DOCKER_MALWARE_IMAGE", "malware-detector:latest")
DOCKER_TIMEOUT = int(os.getenv("DOCKER_TIMEOUT", "300"))  # 5 minutes default

# --- HuggingFace Configuration ---
HF_MODEL_NAME = os.getenv("HF_MODEL_NAME", "distilbert-base-uncased")
HF_CACHE_DIR = os.path.join(MODELS_DIR, "transformers_cache")
HF_MAX_LENGTH = 512
HF_BATCH_SIZE = 8

# --- API Keys ---
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")

# --- Summarization Settings ---
SUMMARIZATION_TEMPERATURE = 0.5
SUMMARIZATION_MAX_TOKENS = 2000
