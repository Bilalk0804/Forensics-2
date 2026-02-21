"""
NLP file-analysis service.

Manages the upload → extract text → analyse pipeline
used by the NLPAnalysis.tsx frontend page.
"""

import json
import logging
import os
import shutil
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# In-memory job store (swap for DB in production)
_nlp_jobs: dict[str, dict] = {}

# Temp directory for uploaded files
UPLOAD_DIR = Path(tempfile.gettempdir()) / "sentinel_nlp_uploads"
UPLOAD_DIR.mkdir(exist_ok=True)


def create_job(filenames: list[str], file_paths: list[str]) -> str:
    """Register a new NLP analysis job and return its ID."""
    job_id = str(uuid.uuid4())
    _nlp_jobs[job_id] = {
        "jobId": job_id,
        "status": "uploaded",
        "filenames": filenames,
        "file_paths": file_paths,
        "created_at": datetime.utcnow().isoformat(),
        "result": None,
        "error": None,
    }
    return job_id


def get_job(job_id: str) -> Optional[dict]:
    return _nlp_jobs.get(job_id)


async def save_uploaded_files(files) -> tuple[list[str], list[str]]:
    """
    Save uploaded UploadFile objects to a temporary directory.

    Returns (filenames, file_paths).
    """
    job_dir = UPLOAD_DIR / str(uuid.uuid4())
    job_dir.mkdir(parents=True, exist_ok=True)

    filenames = []
    file_paths = []
    for f in files:
        dest = job_dir / f.filename
        data = await f.read()
        with open(dest, "wb") as out:
            out.write(data)
        filenames.append(f.filename)
        file_paths.append(str(dest))

    return filenames, file_paths


def extract_text(file_path: str) -> str:
    """
    Extract plain text from a file (PDF, DOCX, TXT, CSV, JSON).
    """
    path = Path(file_path)
    ext = path.suffix.lower()

    try:
        if ext == ".txt":
            return path.read_text(encoding="utf-8", errors="replace")

        elif ext == ".json":
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            return json.dumps(data, indent=2)

        elif ext == ".csv":
            return path.read_text(encoding="utf-8", errors="replace")

        elif ext == ".pdf":
            try:
                from PyPDF2 import PdfReader

                reader = PdfReader(str(path))
                pages = [page.extract_text() or "" for page in reader.pages]
                return "\n\n".join(pages)
            except ImportError:
                logger.warning("PyPDF2 not installed — cannot extract PDF text")
                return ""

        elif ext in (".docx", ".doc"):
            try:
                from docx import Document

                doc = Document(str(path))
                return "\n".join(p.text for p in doc.paragraphs)
            except ImportError:
                logger.warning("python-docx not installed — cannot extract DOCX text")
                return ""

        else:
            # Try reading as plain text
            return path.read_text(encoding="utf-8", errors="replace")

    except Exception as exc:
        logger.error("Text extraction failed for %s: %s", path.name, exc)
        return ""


def run_analysis(job_id: str) -> dict:
    """
    Run NLP analysis on all files in a job.
    Called synchronously (wrapped in asyncio.to_thread by the router).

    Returns the job result dict.
    """
    from api.services.model_registry import ModelRegistry

    job = _nlp_jobs.get(job_id)
    if not job:
        raise ValueError(f"Job {job_id} not found")

    job["status"] = "running"

    try:
        text_model = ModelRegistry.get("text")
    except RuntimeError:
        text_model = None

    file_results = []
    total_evidence = 0
    high_risk_files = []

    for filepath, filename in zip(job["file_paths"], job["filenames"]):
        text = extract_text(filepath)

        if not text.strip():
            file_results.append({
                "filename": filename,
                "status": "skipped",
                "reason": "no-text-content",
            })
            continue

        if text_model:
            analysis = text_model.predict(text)
        else:
            logger.warning("Text model not available for NLP analysis on %s", filename)
            analysis = {
                "label": "model-unavailable",
                "confidence": 0.0,
                "tokens_processed": len(text.split()),
                "entities": [],
                "summary": "",
                "categories": [],
                "risk_level": "UNKNOWN",
                "error": "NLP text model failed to load at startup. Check server logs.",
            }

        evidence_count = len(analysis.get("entities", []))
        total_evidence += evidence_count

        risk = analysis.get("risk_level", "LOW")
        if risk in ("HIGH", "CRITICAL"):
            high_risk_files.append(filename)

        file_results.append({
            "filename": filename,
            "status": "analyzed",
            "risk_level": risk,
            "evidence_count": evidence_count,
            "label": analysis.get("label", ""),
            "confidence": analysis.get("confidence", 0.0),
            "summary": analysis.get("summary", ""),
            "entities": analysis.get("entities", []),
            "categories": analysis.get("categories", []),
        })

    # Overall risk
    if high_risk_files:
        overall_risk = "HIGH"
    elif total_evidence > 10:
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"

    result = {
        "success": True,
        "jobId": job_id,
        "status": "completed",
        "summary": {
            "files_analyzed": len(file_results),
            "total_evidence": total_evidence,
            "overall_risk": overall_risk,
            "high_risk_files": high_risk_files,
        },
        "file_results": file_results,
    }

    job["status"] = "completed"
    job["result"] = result
    return result
