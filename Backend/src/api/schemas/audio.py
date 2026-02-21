"""Audio analysis response schemas."""
from pydantic import BaseModel, Field


class AudioAnalyzeResponse(BaseModel):
    """Response from audio analysis."""
    label: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    filename: str = ""
    size_bytes: int = 0
    transcription: str = ""
    duration_seconds: float = 0.0
