"""NLP file-analysis request/response schemas (used by NLPAnalysis.tsx)."""
from pydantic import BaseModel, Field
from typing import Any, Optional


class NLPUploadResponse(BaseModel):
    """Response from file upload."""
    jobId: str
    filenames: list[str]
    message: str = "Files uploaded successfully"


class NLPFileSummary(BaseModel):
    """Summary for the NLP analysis result."""
    files_analyzed: int
    total_evidence: int
    overall_risk: str
    high_risk_files: list[str] = []


class NLPFileResult(BaseModel):
    """Per-file NLP analysis result."""
    filename: str
    status: str
    risk_level: Optional[str] = None
    evidence_count: Optional[int] = None
    label: Optional[str] = None
    confidence: Optional[float] = None
    summary: Optional[str] = None
    entities: Optional[list[dict[str, Any]]] = None
    categories: Optional[list[dict[str, Any]]] = None
    reason: Optional[str] = None


class NLPAnalysisResponse(BaseModel):
    """Response from NLP analysis."""
    success: bool
    jobId: str
    status: str
    summary: NLPFileSummary | None = None
    file_results: list[NLPFileResult] | None = None
    reportPath: str | None = None
    error: str | None = None
