"""
NLP file-analysis router.

Endpoints:
  POST /api/nlp/upload         — Upload files, returns jobId
  POST /api/nlp/analyze/{id}   — Run NLP analysis on uploaded files
  GET  /api/nlp/report/{id}    — Download analysis report (JSON)
"""

import asyncio
import logging

from fastapi import APIRouter, File, UploadFile, HTTPException, status
from api.schemas.nlp import NLPUploadResponse, NLPAnalysisResponse
from api.services import nlp_service

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/upload",
    response_model=NLPUploadResponse,
    status_code=status.HTTP_200_OK,
    summary="Upload documents for NLP analysis",
)
async def upload_files(files: list[UploadFile] = File(..., description="Documents to analyse")):
    """
    Upload one or more documents for NLP evidence extraction.

    Supported formats: PDF, DOCX, TXT, CSV, JSON.

    Returns a jobId to use with /analyze/{jobId}.
    """
    if not files:
        raise HTTPException(400, "No files provided")

    filenames, file_paths = await nlp_service.save_uploaded_files(files)
    job_id = nlp_service.create_job(filenames, file_paths)

    return NLPUploadResponse(jobId=job_id, filenames=filenames)


@router.post(
    "/analyze/{job_id}",
    response_model=NLPAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Run NLP analysis on uploaded files",
)
async def analyze_job(job_id: str):
    """
    Run full NLP analysis (NER, summarisation, classification) on all
    files uploaded under the given jobId.
    """
    job = nlp_service.get_job(job_id)
    if job is None:
        raise HTTPException(404, f"Job {job_id} not found")

    if job["status"] == "completed" and job.get("result"):
        return NLPAnalysisResponse(**job["result"])

    try:
        result = await asyncio.to_thread(nlp_service.run_analysis, job_id)
        return NLPAnalysisResponse(**result)
    except Exception as exc:
        logger.error("NLP analysis failed: %s", exc)
        raise HTTPException(500, f"Analysis failed: {exc}")


@router.get(
    "/report/{job_id}",
    summary="Download analysis report",
)
async def get_report(job_id: str):
    """Return the full analysis report as JSON."""
    job = nlp_service.get_job(job_id)
    if job is None:
        raise HTTPException(404, f"Job {job_id} not found")

    if job["status"] != "completed" or not job.get("result"):
        raise HTTPException(400, "Analysis not yet completed")

    return job["result"]
