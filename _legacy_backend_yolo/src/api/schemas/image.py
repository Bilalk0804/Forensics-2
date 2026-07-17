"""Image classification request/response schemas."""
from pydantic import BaseModel, Field


class DetectionResult(BaseModel):
    """A single YOLO object detection."""
    class_name: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    bbox: list[float] = []


class ImageClassifyResponse(BaseModel):
    """Response from image classification."""
    label: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    filename: str = ""
    size_bytes: int = 0
    detections: list[DetectionResult] = []
    violence_detected: bool = False
    violence_score: float = Field(0.0, ge=0.0, le=1.0)
    risk_level: str = "LOW"
    detection_count: int = 0
