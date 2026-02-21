"""Forensic analysis workflow router with background task execution."""
import asyncio
import logging
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, status
from pydantic import BaseModel, Field

router = APIRouter()
logger = logging.getLogger(__name__)

# In-memory job cache (replace with database in production)
job_cache: dict = {}


class ForensicAnalysisRequest(BaseModel):
    """Request for forensic analysis."""
    evidencePath: str = Field(..., description="Path to evidence directory")
    outputPath: Optional[str] = Field(None, description="Path to output directory")
    selectedModels: list[str] = Field(default_factory=list, description="Models to run")


class JobStatus(BaseModel):
    """Status of an analysis job."""
    jobId: str
    status: str  # queued, running, completed, failed
    progress: float
    results: Optional[dict] = None
    error: Optional[str] = None


# ── Background worker ──────────────────────────────────────────────────
def _run_forensic_job(job_id: str, evidence_path: str, selected_models: list[str]):
    """Execute forensic analysis in background thread."""
    import os
    from pathlib import Path

    job = job_cache.get(job_id)
    if not job:
        return

    job["status"] = "running"
    results = {}
    model_count = len(selected_models)

    try:
        from api.services.model_registry import ModelRegistry

        # Collect files from evidence path
        evidence_dir = Path(evidence_path)
        if not evidence_dir.exists():
            job["status"] = "failed"
            job["error"] = f"Evidence path not found: {evidence_path}"
            return

        all_files = []
        if evidence_dir.is_file():
            all_files = [evidence_dir]
        else:
            all_files = [f for f in evidence_dir.rglob("*") if f.is_file()]

        if not all_files:
            job["status"] = "failed"
            job["error"] = "No files found in evidence path"
            return

        total_steps = model_count * len(all_files)
        completed_steps = 0

        for model_key in selected_models:
            model_results = []
            try:
                model = ModelRegistry.get(model_key)
            except RuntimeError:
                results[model_key] = {"status": "model-unavailable", "files": []}
                completed_steps += len(all_files)
                job["progress"] = round(completed_steps / max(total_steps, 1) * 100, 1)
                continue

            for file_path in all_files:
                try:
                    if model_key == "text":
                        text = file_path.read_text(encoding="utf-8", errors="replace")
                        result = model.predict(text)
                    elif model_key in ("vision", "deepfake"):
                        if file_path.suffix.lower() in (".jpg", ".jpeg", ".png", ".bmp", ".webp", ".tiff"):
                            data = file_path.read_bytes()
                            result = model.predict(data)
                        else:
                            result = {"status": "skipped", "reason": "not-an-image"}
                    elif model_key in ("malware", "file"):
                        data = file_path.read_bytes()
                        if model_key == "file":
                            result = model.predict(data, filename=file_path.name)
                        else:
                            result = model.predict(data)
                    elif model_key == "audio":
                        if file_path.suffix.lower() in (".wav", ".mp3", ".ogg", ".flac", ".m4a"):
                            data = file_path.read_bytes()
                            result = model.predict(data)
                        else:
                            result = {"status": "skipped", "reason": "not-audio"}
                    else:
                        result = {"status": "unknown-model"}

                    model_results.append({
                        "file": str(file_path.name),
                        "result": result,
                    })
                except Exception as exc:
                    model_results.append({
                        "file": str(file_path.name),
                        "error": str(exc),
                    })

                completed_steps += 1
                job["progress"] = round(completed_steps / max(total_steps, 1) * 100, 1)

            # Count threats for this model
            threats = sum(
                1 for r in model_results
                if r.get("result", {}).get("is_malicious")
                or r.get("result", {}).get("risk_level") in ("HIGH", "CRITICAL")
                or r.get("result", {}).get("violence_detected")
                or r.get("result", {}).get("is_deepfake")
            )

            results[model_key] = {
                "status": "completed",
                "files_analyzed": len(model_results),
                "threats": threats,
                "details": model_results,
            }

        job["status"] = "completed"
        job["progress"] = 100
        job["results"] = results

    except Exception as exc:
        logger.error("Forensic job %s failed: %s", job_id, exc)
        job["status"] = "failed"
        job["error"] = str(exc)


# ── Endpoints ──────────────────────────────────────────────────────────

@router.post("/analyze", status_code=status.HTTP_202_ACCEPTED, tags=["Forensics"])
async def submit_analysis(payload: ForensicAnalysisRequest, background_tasks: BackgroundTasks):
    """
    Submit a forensic analysis job.

    The job runs in the background. Use /status/{jobId} to track progress.
    """
    if not payload.evidencePath:
        raise HTTPException(400, "evidencePath is required")

    if not payload.selectedModels:
        raise HTTPException(400, "At least one model must be selected")

    job_id = str(uuid.uuid4())
    job_cache[job_id] = {
        "jobId": job_id,
        "status": "queued",
        "progress": 0,
        "results": None,
        "error": None,
        "config": {
            "evidencePath": payload.evidencePath,
            "outputPath": payload.outputPath,
            "selectedModels": payload.selectedModels,
        },
        "startTime": datetime.utcnow().isoformat(),
    }

    # Launch background task
    background_tasks.add_task(
        _run_forensic_job, job_id, payload.evidencePath, payload.selectedModels
    )

    return {
        "jobId": job_id,
        "status": "queued",
        "message": "Analysis job submitted",
    }


@router.get("/status/{job_id}", tags=["Forensics"])
async def get_job_status(job_id: str):
    """Get the status of an analysis job."""
    if job_id not in job_cache:
        raise HTTPException(404, f"Job {job_id} not found")
    return job_cache[job_id]


@router.get("/jobs", tags=["Forensics"])
async def list_jobs():
    """List all active and completed jobs."""
    return {"jobs": list(job_cache.values())}


@router.delete("/jobs/{job_id}", tags=["Forensics"])
async def delete_job(job_id: str):
    """Delete a job."""
    if job_id not in job_cache:
        raise HTTPException(404, f"Job {job_id} not found")
    del job_cache[job_id]
    return {"success": True}


@router.get("/models", tags=["Forensics"])
async def get_available_models():
    """Get list of available forensic analysis models."""
    from api.services.model_registry import ModelRegistry

    loaded = ModelRegistry.loaded_models()

    models = {
        "vision": {
            "id": "vision",
            "name": "Vision Analysis",
            "description": "YOLO object detection + ViT violence classifier",
            "capabilities": ["object-detection", "violence-detection", "scene-analysis"],
            "enabled": "vision" in loaded,
        },
        "text": {
            "id": "text",
            "name": "Text / NLP Analysis",
            "description": "BERT NER + BART summarisation + zero-shot classification",
            "capabilities": ["entity-extraction", "summarization", "threat-classification"],
            "enabled": "text" in loaded,
        },
        "malware": {
            "id": "malware",
            "name": "Malware Detection",
            "description": "File hashing + PE analysis + YARA rule scanning",
            "capabilities": ["hash-calculation", "pe-analysis", "yara-scanning"],
            "enabled": "malware" in loaded,
        },
        "file": {
            "id": "file",
            "name": "File Analysis",
            "description": "File metadata, MIME detection, extension analysis",
            "capabilities": ["hash-calculation", "metadata-extraction", "suspicious-detection"],
            "enabled": "file" in loaded,
        },
        "audio": {
            "id": "audio",
            "name": "Audio Analysis",
            "description": "Whisper speech-to-text transcription",
            "capabilities": ["speech-to-text", "audio-transcription"],
            "enabled": "audio" in loaded,
        },
        "deepfake": {
            "id": "deepfake",
            "name": "Deepfake Detection",
            "description": "SigLIP-based deepfake classifier for images and video",
            "capabilities": ["deepfake-detection", "frame-analysis"],
            "enabled": "deepfake" in loaded,
        },
    }

    return {"models": models}
