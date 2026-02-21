"""Deepfake / video analysis response schemas."""
from pydantic import BaseModel, Field


class DeepfakeDetectResponse(BaseModel):
    """Response from deepfake detection."""
    is_deepfake: bool
    confidence: float = Field(..., ge=0.0, le=1.0)
    label: str = ""
    filename: str = ""
    size_bytes: int = 0
