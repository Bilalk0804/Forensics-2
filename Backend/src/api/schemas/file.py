"""File malware scanning request/response schemas."""
from pydantic import BaseModel, Field
from typing import Optional


class MalwareScanResponse(BaseModel):
    """Response from malware scan."""
    is_malicious: bool
    confidence: float = Field(..., ge=0.0, le=1.0)
    threat_label: str
    threat_family: str | None = None
    filename: str = ""
    size_bytes: int = 0
    hashes: dict[str, str] = {}
    pe_info: dict | None = None
    yara_matches: list[str] = []
