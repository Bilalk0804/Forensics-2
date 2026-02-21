"""
Asset Analyzer Module
Intelligently analyzes assets and determines which analysis pipelines to activate.
Routes files to appropriate forensic models based on content characteristics.
"""

import os
import mimetypes
import logging
from typing import Dict, List, Tuple, Any, Optional
from pathlib import Path
import hashlib
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("SENTINEL_ASSET_ANALYZER")


class AssetType(Enum):
    """Asset type enumeration."""
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    TEXT = "text"
    BINARY = "binary"
    ARCHIVE = "archive"
    DATABASE = "database"
    DOCUMENT = "document"
    UNKNOWN = "unknown"


class RiskLevel(Enum):
    """Risk level enumeration."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class AssetMetadata:
    """Metadata for an analyzed asset."""
    file_path: str
    file_size: int
    file_hash: str
    mime_type: str
    asset_type: AssetType
    file_extension: str
    is_suspicious: bool = False
    risk_level: RiskLevel = RiskLevel.LOW
    characteristics: Dict[str, Any] = field(default_factory=dict)
    recommended_models: List[str] = field(default_factory=list)
    recommended_pipelines: List[str] = field(default_factory=list)
    analysis_flags: List[str] = field(default_factory=list)


class AssetAnalyzer:
    """Analyzes assets and recommends analysis strategies."""

    def __init__(self):
        """Initialize Asset Analyzer."""
        self.magic_signatures = self._init_magic_signatures()
        self.suspicious_patterns = self._init_suspicious_patterns()
        logger.info("AssetAnalyzer initialized")

    def _init_magic_signatures(self) -> Dict[bytes, str]:
        """Initialize file magic signatures for forensic detection."""
        return {
            # Image formats
            b'\x89PNG\r\n\x1a\n': 'image/png',
            b'\xff\xd8\xff': 'image/jpeg',
            b'GIF8': 'image/gif',
            b'RIFF': 'image/wav',  # Can be RIFF video too
            
            # Video formats
            b'\x00\x00\x00\x20ftyp': 'video/mp4',
            b'\x00\x00\x00\x18ftypMSNV': 'video/avi',
            b'RIFF': 'video/avi',
            
            # PDF
            b'%PDF': 'application/pdf',
            
            # Office
            b'PK\x03\x04': 'application/zip',  # Also Office formats
            
            # Executables
            b'MZ': 'application/x-executable',
            
            # Archives
            b'\x1f\x8b\x08': 'application/gzip',
            b'BZh': 'application/x-bzip2',
            b'7z\xbc\xaf\x27\x1c': 'application/x-7z-compressed',
            b'Rar!': 'application/x-rar-compressed',
        }

    def _init_suspicious_patterns(self) -> Dict[str, List[str]]:
        """Initialize patterns indicating suspicious files."""
        return {
            "hidden_extensions": [
                ".exe.txt", ".dll.jpg", ".bat.pdf", ".js.doc"
            ],
            "suspicious_keywords": [
                "crack", "keygen", "patch", "warez", "stolen",
                "ransomware", "malware", "trojan", "backdoor"
            ],
            "double_extensions": [
                ".pdf.exe", ".doc.exe", ".jpg.exe", ".png.exe"
            ],
            "null_byte_indicators": [
                "file\x00.jpg", "image\x00.exe"
            ]
        }

    def analyze_asset(self, file_path: str) -> AssetMetadata:
        """
        Analyze a file and generate metadata with recommendations.
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            AssetMetadata with analysis results
        """
        try:
            path_obj = Path(file_path)
            
            if not path_obj.exists():
                logger.error(f"File not found: {file_path}")
                return self._create_error_metadata(file_path)

            # Gather basic information
            file_size = path_obj.stat().st_size
            file_hash = self._calculate_hash(file_path)
            mime_type = self._detect_mime_type(file_path)
            asset_type = self._determine_asset_type(file_path, mime_type)
            extension = path_obj.suffix.lower()

            # Analyze characteristics
            characteristics = self._analyze_characteristics(
                file_path, asset_type, mime_type, file_size
            )

            # Check for suspicious indicators
            is_suspicious, risk_level, flags = self._check_suspicious_indicators(
                file_path, mime_type, characteristics
            )

            # Recommend models and pipelines
            models = self._recommend_models(asset_type, characteristics)
            pipelines = self._recommend_pipelines(asset_type)

            metadata = AssetMetadata(
                file_path=file_path,
                file_size=file_size,
                file_hash=file_hash,
                mime_type=mime_type,
                asset_type=asset_type,
                file_extension=extension,
                is_suspicious=is_suspicious,
                risk_level=risk_level,
                characteristics=characteristics,
                recommended_models=models,
                recommended_pipelines=pipelines,
                analysis_flags=flags
            )

            logger.info(
                f"Analyzed: {path_obj.name} | Type: {asset_type.value} | "
                f"Risk: {risk_level.value} | Models: {len(models)}"
            )

            return metadata

        except Exception as e:
            logger.error(f"Error analyzing asset {file_path}: {e}")
            return self._create_error_metadata(file_path)

    def _calculate_hash(self, file_path: str, algorithm: str = 'sha256') -> str:
        """Calculate file hash."""
        hash_obj = hashlib.new(algorithm)
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            logger.warning(f"Could not calculate hash for {file_path}: {e}")
            return ""

    def _detect_mime_type(self, file_path: str) -> str:
        """Detect MIME type using magic numbers and extension."""
        try:
            # Try magic number detection first (more reliable)
            with open(file_path, 'rb') as f:
                magic = f.read(512)
            
            for sig, mime in self.magic_signatures.items():
                if magic.startswith(sig):
                    return mime
            
            # Fallback to extension-based detection
            mime, _ = mimetypes.guess_type(file_path)
            return mime or 'application/octet-stream'
        
        except Exception as e:
            logger.warning(f"MIME detection failed for {file_path}: {e}")
            return 'application/octet-stream'

    def _determine_asset_type(self, file_path: str, mime_type: str) -> AssetType:
        """Determine asset type from MIME type and extension."""
        mime_lower = mime_type.lower()
        ext = Path(file_path).suffix.lower()

        if mime_lower.startswith('image/'):
            return AssetType.IMAGE
        elif mime_lower.startswith('video/'):
            return AssetType.VIDEO
        elif mime_lower.startswith('audio/'):
            return AssetType.AUDIO
        elif mime_lower.startswith('text/') or ext in ['.txt', '.log', '.csv']:
            return AssetType.TEXT
        elif mime_lower in ['application/pdf', 'application/msword']:
            return AssetType.DOCUMENT
        elif ext in ['.zip', '.rar', '.7z', '.tar', '.gz']:
            return AssetType.ARCHIVE
        elif ext in ['.db', '.sqlite', '.mdb']:
            return AssetType.DATABASE
        elif mime_lower in ['application/x-executable', 'application/x-dosexec']:
            return AssetType.BINARY
        else:
            return AssetType.UNKNOWN

    def _analyze_characteristics(
        self,
        file_path: str,
        asset_type: AssetType,
        mime_type: str,
        file_size: int
    ) -> Dict[str, Any]:
        """Analyze file characteristics."""
        characteristics = {
            "file_size_mb": file_size / 1e6,
            "is_large": file_size > 1e9,  # > 1GB
        }

        try:
            if asset_type == AssetType.IMAGE:
                characteristics.update(self._analyze_image(file_path))
            elif asset_type == AssetType.VIDEO:
                characteristics.update(self._analyze_video(file_path))
            elif asset_type == AssetType.DOCUMENT:
                characteristics.update(self._analyze_document(file_path))
            elif asset_type == AssetType.BINARY:
                characteristics.update(self._analyze_binary(file_path))
        except Exception as e:
            logger.warning(f"Error analyzing characteristics: {e}")

        return characteristics

    def _analyze_image(self, file_path: str) -> Dict[str, Any]:
        """Analyze image-specific characteristics."""
        try:
            from PIL import Image
            img = Image.open(file_path)
            return {
                "dimensions": img.size,
                "mode": img.mode,
                "format": img.format,
                "has_exif": bool(img._getexif() if hasattr(img, '_getexif') else None),
            }
        except Exception as e:
            logger.warning(f"Could not analyze image {file_path}: {e}")
            return {}

    def _analyze_video(self, file_path: str) -> Dict[str, Any]:
        """Analyze video-specific characteristics."""
        try:
            import cv2
            cap = cv2.VideoCapture(file_path)
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            fps = cap.get(cv2.CAP_PROP_FPS)
            width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
            height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
            cap.release()
            
            return {
                "frame_count": frame_count,
                "fps": fps,
                "duration_seconds": frame_count / fps if fps > 0 else 0,
                "resolution": f"{width}x{height}",
            }
        except Exception as e:
            logger.warning(f"Could not analyze video {file_path}: {e}")
            return {}

    def _analyze_document(self, file_path: str) -> Dict[str, Any]:
        """Analyze document-specific characteristics."""
        return {
            "is_office": file_path.endswith(('.docx', '.xlsx', '.pptx')),
            "is_pdf": file_path.endswith('.pdf'),
        }

    def _analyze_binary(self, file_path: str) -> Dict[str, Any]:
        """Analyze binary-specific characteristics."""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(1024)
            
            return {
                "has_dos_header": header.startswith(b'MZ'),
                "entropy": self._calculate_entropy(header),
                "suspicious_strings": self._find_suspicious_strings(header),
            }
        except Exception as e:
            logger.warning(f"Could not analyze binary {file_path}: {e}")
            return {}

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        import math
        if not data:
            return 0.0
        
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        
        entropy = 0.0
        for count in freq.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        
        return entropy

    def _find_suspicious_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract suspicious strings from binary data."""
        strings = []
        try:
            current = b''
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current += bytes([byte])
                else:
                    if len(current) >= min_length:
                        strings.append(current.decode('ascii', errors='ignore'))
                    current = b''
            
            suspicious = [s for s in strings if any(
                keyword in s.lower() for keyword in ['password', 'admin', 'hack', 'key']
            )]
            return suspicious[:5]  # Return top 5
        except Exception as e:
            logger.warning(f"String extraction failed: {e}")
            return []

    def _check_suspicious_indicators(
        self,
        file_path: str,
        mime_type: str,
        characteristics: Dict[str, Any]
    ) -> Tuple[bool, RiskLevel, List[str]]:
        """Check for suspicious indicators."""
        flags = []
        risk_score = 0

        # Check for double extensions
        file_name = Path(file_path).name
        if file_name.count('.') > 1:
            flags.append("DOUBLE_EXTENSION")
            risk_score += 2

        # Check for suspicious keywords
        for keyword in self.suspicious_patterns["suspicious_keywords"]:
            if keyword.lower() in file_name.lower():
                flags.append(f"SUSPICIOUS_KEYWORD: {keyword}")
                risk_score += 1

        # Check MIME type mismatch
        ext_mime = mimetypes.guess_type(file_path)[0]
        if ext_mime and ext_mime != mime_type:
            flags.append("MIME_TYPE_MISMATCH")
            risk_score += 1

        # Check file size anomalies
        file_size_mb = characteristics.get("file_size_mb", 0)
        if file_size_mb > 5000:  # > 5GB
            flags.append("UNUSUALLY_LARGE_FILE")
            risk_score += 1

        # Determine risk level
        if risk_score >= 3:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 2:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 1:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

        is_suspicious = risk_score > 0

        return is_suspicious, risk_level, flags

    def _recommend_models(
        self,
        asset_type: AssetType,
        characteristics: Dict[str, Any]
    ) -> List[str]:
        """Recommend models based on asset type."""
        models = []

        if asset_type == AssetType.IMAGE:
            models = [
                "yolo_v8",  # Object detection
                "efficientnet",  # Classification
                "lstm_deepfake"  # Deepfake detection
            ]
        elif asset_type == AssetType.VIDEO:
            models = [
                "lstm_deepfake",  # Deepfake detection
                "yolo_v8",  # Frame analysis
                "wav2vec_speech"  # Audio track analysis
            ]
        elif asset_type == AssetType.AUDIO:
            models = [
                "wav2vec_speech",  # Speech recognition
            ]
        elif asset_type == AssetType.TEXT or asset_type == AssetType.DOCUMENT:
            models = [
                "roberta_toxicity",  # Content analysis
                "bert_ner",  # Entity extraction
                "distilbert_classification"  # Classification
            ]
        elif asset_type == AssetType.BINARY:
            models = [
                "tabnet_metadata"  # Binary analysis
            ]

        return models

    def _recommend_pipelines(self, asset_type: AssetType) -> List[str]:
        """Recommend pipelines based on asset type."""
        pipelines = ["file_pipeline"]  # Always run file pipeline

        if asset_type == AssetType.IMAGE or asset_type == AssetType.VIDEO:
            pipelines.append("vision_pipeline")
        elif asset_type == AssetType.TEXT or asset_type == AssetType.DOCUMENT:
            pipelines.append("text_pipeline")
        elif asset_type == AssetType.AUDIO:
            pipelines.append("text_pipeline")  # For speech-to-text

        return pipelines

    def _create_error_metadata(self, file_path: str) -> AssetMetadata:
        """Create metadata for error case."""
        return AssetMetadata(
            file_path=file_path,
            file_size=0,
            file_hash="",
            mime_type="application/octet-stream",
            asset_type=AssetType.UNKNOWN,
            file_extension="",
            is_suspicious=True,
            risk_level=RiskLevel.INFO,
            analysis_flags=["ANALYSIS_ERROR"]
        )

    def batch_analyze(self, file_paths: List[str]) -> List[AssetMetadata]:
        """Analyze multiple assets."""
        return [self.analyze_asset(path) for path in file_paths]

    def filter_by_type(
        self,
        assets: List[AssetMetadata],
        asset_type: AssetType
    ) -> List[AssetMetadata]:
        """Filter assets by type."""
        return [a for a in assets if a.asset_type == asset_type]

    def filter_by_risk(
        self,
        assets: List[AssetMetadata],
        min_risk: RiskLevel
    ) -> List[AssetMetadata]:
        """Filter assets by minimum risk level."""
        risk_order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        min_idx = risk_order.index(min_risk)
        return [a for a in assets if risk_order.index(a.risk_level) >= min_idx]
