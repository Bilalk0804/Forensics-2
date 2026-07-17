"""Text analysis request/response schemas."""
from pydantic import BaseModel, Field
from typing import Optional


class TextAnalyzeRequest(BaseModel):
    """Request to analyze text."""
    text: str = Field(..., min_length=1, max_length=100_000, description="Raw text to analyze")

    model_config = {"json_schema_extra": {"example": {"text": "Suspicious powershell -enc payload"}}}


class EntityResult(BaseModel):
    """A single NER entity."""
    text: str
    entity_type: str
    start: int
    end: int
    confidence: float = Field(..., ge=0.0, le=1.0)


class CategoryResult(BaseModel):
    """A zero-shot classification result."""
    label: str
    score: float = Field(..., ge=0.0, le=1.0)


class TextAnalyzeResponse(BaseModel):
    """Response from text analysis."""
    label: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    tokens_processed: int
    entities: list[EntityResult] = []
    summary: str = ""
    categories: list[CategoryResult] = []
    risk_level: str = "LOW"
