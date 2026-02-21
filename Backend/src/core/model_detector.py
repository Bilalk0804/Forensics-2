"""
Model Auto-Detection Module
============================
Automatically discovers and validates AI model files in the MODELS directory.
"""

import os
import glob
from typing import Dict, List, Optional
from pathlib import Path


class ModelDetector:
    """Auto-detects model files in the MODELS directory."""
    
    def __init__(self, models_root: str):
        """
        Initialize model detector.
        
        Args:
            models_root: Root directory containing model files
        """
        self.models_root = models_root
        self.models = {}
        
    def scan_models(self) -> Dict[str, str]:
        """
        Scan MODELS directory and auto-detect model files.
        
        Returns:
            Dictionary of model type -> file path
        """
        models = {}
        
        # YOLO models - look in VIdeo, vision, or any subdirectory
        yolo_patterns = [
            "**/*yolo*.pt",
            "**/*yolo*.keras",
            "**/*lstm*.keras",
            "**/best*.keras",
            "**/yolov*.pt",
        ]
        
        for pattern in yolo_patterns:
            matches = glob.glob(os.path.join(self.models_root, pattern), recursive=True)
            if matches:
                models['yolo'] = matches[0]
                break
        
        # Violence detection model
        violence_patterns = [
            "**/*violence*.pth",
            "**/*violence*.pt",
            "**/*safety*.pth",
            "Image/**/*.pth",
        ]
        
        for pattern in violence_patterns:
            matches = glob.glob(os.path.join(self.models_root, pattern), recursive=True)
            if matches:
                models['violence'] = matches[0]
                break
        
        # Malware PE classifier
        pe_patterns = [
            "**/Malware*/**/classifier.pkl",
            "**/classifier.pkl",
        ]
        
        for pattern in pe_patterns:
            matches = glob.glob(os.path.join(self.models_root, pattern), recursive=True)
            if matches:
                models['malware_pe'] = matches[0]
                break
        
        # URL malware classifier
        url_patterns = [
            "**/Malware*/**/pickel_model.pkl",
            "**/pickel_model.pkl",
        ]
        
        for pattern in url_patterns:
            matches = glob.glob(os.path.join(self.models_root, pattern), recursive=True)
            if matches:
                models['malware_url'] = matches[0]
                break
        
        # URL vectorizer
        vec_patterns = [
            "**/Malware*/**/pickel_vector.pkl",
            "**/pickel_vector.pkl",
        ]
        
        for pattern in vec_patterns:
            matches = glob.glob(os.path.join(self.models_root, pattern), recursive=True)
            if matches:
                models['url_vectorizer'] = matches[0]
                break
        
        # DeepFake models
        deepfake_patterns = [
            "**/DeepFake/**/*.h5",
            "**/DeepFake/**/*.keras",
            "**/DeepFake/**/*.pth",
        ]
        
        for pattern in deepfake_patterns:
            matches = glob.glob(os.path.join(self.models_root, pattern), recursive=True)
            if matches:
                models['deepfake'] = matches[0]
                break
        
        # HuggingFace models (transformers)
        hf_patterns = [
            "**/transformers/**",
            "**/Text/**/*.bin",
            "**/nlp/**/*.bin",
        ]
        
        for pattern in hf_patterns:
            matches = glob.glob(os.path.join(self.models_root, pattern), recursive=True)
            if matches:
                # Check if it's a HuggingFace model directory
                for match in matches:
                    if os.path.isdir(match) and os.path.exists(os.path.join(match, 'config.json')):
                        models['huggingface'] = match
                        break
                    elif match.endswith('.bin'):
                        models['huggingface'] = match
                        break
        
        self.models = models
        return models
    
    def get_model_info(self) -> List[Dict[str, str]]:
        """
        Get detailed information about detected models.
        
        Returns:
            List of model information dictionaries
        """
        info = []
        
        for model_type, path in self.models.items():
            size_mb = os.path.getsize(path) / (1024 * 1024) if os.path.isfile(path) else 0
            
            info.append({
                'type': model_type,
                'path': path,
                'size_mb': round(size_mb, 2),
                'exists': os.path.exists(path),
                'is_file': os.path.isfile(path),
                'is_dir': os.path.isdir(path),
            })
        
        return info
    
    def validate_models(self, required: List[str] = None) -> tuple:
        """
        Validate that required models exist.
        
        Args:
            required: List of required model types (None = all detected)
        
        Returns:
            (success: bool, missing: list)
        """
        if not self.models:
            self.scan_models()
        
        if required is None:
            required = ['yolo', 'violence', 'malware_pe', 'malware_url']
        
        missing = []
        for model_type in required:
            if model_type not in self.models:
                missing.append(model_type)
            elif not os.path.exists(self.models[model_type]):
                missing.append(f"{model_type} (path invalid)")
        
        return len(missing) == 0, missing
    
    def print_models(self):
        """Print detected models in formatted output."""
        if not self.models:
            self.scan_models()
        
        print("\n" + "="*70)
        print("DETECTED AI MODELS")
        print("="*70 + "\n")
        
        if not self.models:
            print("No models detected!")
            return
        
        for model_type, path in self.models.items():
            if os.path.isfile(path):
                size_mb = os.path.getsize(path) / (1024 * 1024)
                print(f"[{model_type.upper()}]")
                print(f"  Path: {path}")
                print(f"  Size: {size_mb:.2f} MB")
            else:
                print(f"[{model_type.upper()}]")
                print(f"  Path: {path}")
                print(f"  Type: Directory")
            print()
        
        print("="*70 + "\n")


def auto_detect_models(models_root: str) -> Dict[str, str]:
    """
    Convenience function to auto-detect models.
    
    Args:
        models_root: Root directory containing models
    
    Returns:
        Dictionary of model type -> path
    """
    detector = ModelDetector(models_root)
    return detector.scan_models()


if __name__ == "__main__":
    """Test model detection."""
    import sys
    
    # Use MODELS directory from project root
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    models_root = os.path.join(project_root, "MODELS")
    
    print(f"Scanning for models in: {models_root}\n")
    
    detector = ModelDetector(models_root)
    models = detector.scan_models()
    
    detector.print_models()
    
    # Validate
    success, missing = detector.validate_models()
    
    if success:
        print("All required models found!")
    else:
        print(f"Missing models: {', '.join(missing)}")
        sys.exit(1)
