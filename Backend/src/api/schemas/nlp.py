"""NLP file-analysis request/response schemas (used by NLPAnalysis.tsx)."""
from pydantic import BaseModel, Field


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


class NLPAnalysisResponse(BaseModel):
    """Response from NLP analysis."""
    success: bool
    jobId: str
    status: str
    summary: NLPFileSummary | None = None
    reportPath: str | None = None
    error: str | None = None
