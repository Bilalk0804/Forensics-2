"""Forensic analysis workflow router with background task execution."""
import asyncio
import io
import logging
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, status
from fastapi.responses import StreamingResponse
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
    job["startTime"] = datetime.utcnow().isoformat()   # actual analysis start
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

        # Windows system metadata files that contain no forensic value
        _SKIP_NAMES = {
            "IndexerVolumeGuid", "WPSettings.dat", "Thumbs.db", "desktop.ini",
            "hiberfil.sys", "pagefile.sys", "swapfile.sys", "NTUSER.DAT",
            "ntuser.dat.LOG1", "ntuser.dat.LOG2", "usrclass.dat",
            "usrclass.dat.LOG1", "usrclass.dat.LOG2",
        }
        _SKIP_DIRS = {
            "System Volume Information", "$RECYCLE.BIN", "$Recycle.Bin",
            "Recovery", "WpSystem", "MSOCache",
        }

        all_files = []
        if evidence_dir.is_file():
            all_files = [evidence_dir]
        else:
            all_files = [
                f for f in evidence_dir.rglob("*")
                if f.is_file()
                and f.name not in _SKIP_NAMES
                and not any(part in _SKIP_DIRS for part in f.parts)
            ]

        if not all_files:
            job["status"] = "failed"
            job["error"] = "No files found in evidence path"
            return

        total_steps = model_count * len(all_files)
        completed_steps = 0

        from concurrent.futures import ThreadPoolExecutor, as_completed
        import hashlib as _hl

        # Remote models = network I/O bound → benefit from high parallelism
        # Local models  = CPU bound        → fewer workers to avoid thrashing
        _REMOTE_KEYS = {"text", "vision", "audio", "deepfake"}

        # ── Extension allow-lists per model ──────────────────────────────────
        _TEXT_EXTS = {
            ".txt", ".log", ".csv", ".json", ".xml", ".html", ".htm",
            ".md", ".yaml", ".yml", ".ini", ".cfg", ".conf", ".py",
            ".js", ".ts", ".java", ".c", ".cpp", ".cs", ".sh", ".bat",
            ".ps1", ".sql", ".rtf", ".toml", ".env", ".jsx", ".tsx",
            ".eml", ".msg", ".ics", ".vcf", ".css", ".php", ".rb",
            ".go", ".rs", ".swift", ".kt", ".r", ".m",
        }
        _IMAGE_EXTS = {
            ".jpg", ".jpeg", ".png", ".bmp", ".webp", ".tiff", ".tif",
            ".gif", ".ico", ".svg",
        }
        _AUDIO_EXTS = {
            ".wav", ".mp3", ".ogg", ".flac", ".m4a", ".aac", ".wma",
            ".opus", ".amr",
        }
        _VIDEO_EXTS = {
            ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm",
            ".m4v", ".3gp",
        }
        # Malware model focuses on executables, scripts, office macros, archives
        _MALWARE_EXTS = {
            ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1",
            ".vbs", ".js", ".wsf", ".msi", ".com", ".pif",
            ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm",
            ".ppt", ".pptx", ".pptm", ".pdf",
            ".zip", ".rar", ".7z", ".tar", ".gz", ".iso",
            ".jar", ".apk", ".elf", ".bin", ".dat",
            ".lnk", ".hta", ".inf", ".reg",
        }
        # File model (hash / metadata) can run on anything but skip tiny system junk
        _FILE_SKIP_EXTS = set()  # runs on all files

        # Deepfake model: images + video frames
        _DEEPFAKE_EXTS = _IMAGE_EXTS | _VIDEO_EXTS

        # ── Size limits per model (bytes) ────────────────────────────────────
        _MAX_SIZE = {
            "text":     2 * 1024 * 1024,    # 2 MB — any bigger is not a readable text
            "audio":    10 * 1024 * 1024,   # 10 MB
            "vision":   20 * 1024 * 1024,   # 20 MB
            "deepfake": 20 * 1024 * 1024,   # 20 MB
            "malware":  50 * 1024 * 1024,   # 50 MB
            "file":     100 * 1024 * 1024,  # 100 MB
        }

        # Map model_key → allowed extensions (None = all)
        _EXT_MAP = {
            "text": _TEXT_EXTS,
            "vision": _IMAGE_EXTS,
            "deepfake": _DEEPFAKE_EXTS,
            "audio": _AUDIO_EXTS,
            "malware": _MALWARE_EXTS,
            "file": None,  # runs on everything
        }

        def _should_skip(model_key, file_path):
            """Return (skip: bool, reason: str | None)."""
            # Skip zero-byte files for all models
            try:
                fsize = file_path.stat().st_size
            except OSError:
                return True, "unreadable"
            if fsize == 0:
                return True, "empty-file"

            # Extension filter
            allowed = _EXT_MAP.get(model_key)
            if allowed is not None and file_path.suffix.lower() not in allowed:
                return True, f"not-a-{model_key}-file"

            # Size cap
            max_bytes = _MAX_SIZE.get(model_key, 100 * 1024 * 1024)
            if fsize > max_bytes:
                return True, f"too-large-{fsize // (1024*1024)}MB"

            return False, None

        def _predict_file(model, model_key, file_path):
            """Run one model on one file. Returns (file_name, result_or_error).
            The result dict always includes 'full_path' for image embedding in PDF."""
            try:
                full_path_str = str(file_path)
                if model_key == "text":
                    text = file_path.read_text(encoding="utf-8", errors="replace")
                    res = model.predict(text)
                    res["full_path"] = full_path_str
                    return file_path.name, {"result": res}
                elif model_key in ("vision", "deepfake"):
                    res = model.predict(file_path.read_bytes())
                    res["full_path"] = full_path_str
                    return file_path.name, {"result": res}
                elif model_key in ("malware", "file"):
                    data = file_path.read_bytes()
                    if model_key == "file":
                        res = model.predict(data, filename=file_path.name)
                    else:
                        res = model.predict(data)
                    res["full_path"] = full_path_str
                    return file_path.name, {"result": res}
                elif model_key == "audio":
                    res = model.predict(file_path.read_bytes())
                    res["full_path"] = full_path_str
                    return file_path.name, {"result": res}
                return file_path.name, {"result": {"status": "unknown-model"}}
            except Exception as exc:
                return file_path.name, {"error": str(exc)}

        total_files = len(all_files)
        logger.info("=" * 60)
        logger.info("JOB %s | %d files | models: %s", job_id[:8], total_files, selected_models)
        logger.info("=" * 60)

        for model_key in selected_models:
            model_results = []
            try:
                model = ModelRegistry.get(model_key)
            except RuntimeError:
                logger.warning("[%s] model unavailable — skipping all %d files", model_key.upper(), total_files)
                results[model_key] = {"status": "model-unavailable", "files": []}
                completed_steps += total_files
                job["progress"] = round(completed_steps / max(total_steps, 1) * 100, 1)
                continue

            # ── Pre-filter: only submit relevant files to the thread pool ────
            eligible_files = []
            skipped_results = []
            for fp in all_files:
                skip, reason = _should_skip(model_key, fp)
                if skip:
                    skipped_results.append({"file": fp.name, "result": {"status": "skipped", "reason": reason}})
                else:
                    eligible_files.append(fp)

            eligible_count = len(eligible_files)
            skipped_count = len(skipped_results)
            model_results.extend(skipped_results)
            completed_steps += skipped_count  # instant progress for skipped files
            job["progress"] = round(completed_steps / max(total_steps, 1) * 100, 1)

            if eligible_count == 0:
                logger.info("[%s] Skipped all %d files (no matching extensions)", model_key.upper(), total_files)
                results[model_key] = {
                    "status": "completed",
                    "files_analyzed": len(model_results),
                    "threats": 0,
                    "details": model_results,
                }
                continue

            # Use more workers for remote models (network I/O bound) than local (CPU bound)
            max_workers = 8 if model_key in _REMOTE_KEYS else 4
            logger.info(
                "[%s] Starting — %d eligible files (%d skipped), %d parallel workers",
                model_key.upper(), eligible_count, skipped_count, max_workers,
            )

            model_done = 0
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {
                    pool.submit(_predict_file, model, model_key, fp): fp
                    for fp in eligible_files
                }
                for future in as_completed(futures):
                    file_name, outcome = future.result()
                    model_results.append({"file": file_name, **outcome})
                    model_done += 1
                    completed_steps += 1
                    remaining = eligible_count - model_done
                    pct = round(model_done / eligible_count * 100, 1)
                    status_tag = "error" if "error" in outcome else outcome.get("result", {}).get("label", "ok")
                    logger.info(
                        "[%s] %d/%d done | %d remaining | %.1f%% | %s → %s",
                        model_key.upper(), model_done, eligible_count,
                        remaining, pct, file_name, status_tag,
                    )
                    job["progress"] = round(completed_steps / max(total_steps, 1) * 100, 1)

            logger.info("[%s] ✓ Finished — %d analyzed, %d skipped", model_key.upper(), eligible_count, skipped_count)

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

        job["endTime"] = datetime.utcnow().isoformat()
        job["status"] = "completed"
        job["progress"] = 100
        job["results"] = results
        # Store execution_time on the job for easy frontend access
        try:
            _s = datetime.fromisoformat(job["startTime"])
            _e = datetime.fromisoformat(job["endTime"])
            job["execution_time"] = round((_e - _s).total_seconds(), 2)
        except Exception:
            job["execution_time"] = None
        logger.info("=" * 60)
        logger.info("JOB %s | ✓ COMPLETED | %d files processed", job_id[:8], total_files)
        logger.info("=" * 60)

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
        "startTime": None,   # set when analysis actually begins
        "endTime": None,     # set when analysis completes
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


# ── Report / Export endpoints ──────────────────────────────────────────

def _resolve_image_path(model_key: str, res: dict) -> str:
    """
    Determine the image file path to embed in the PDF for this result.
    - For vision / deepfake on images: use the original file (full_path).
    - For deepfake on videos: use the saved frame path.
    - For other models: no image applicable.
    """
    if model_key in ("vision", "deepfake"):
        # Deepfake video → saved extracted frame
        saved_frame = res.get("saved_frame_path")
        if saved_frame and os.path.isfile(saved_frame):
            return saved_frame
        # Original image file
        full_path = res.get("full_path", "")
        if full_path and os.path.isfile(full_path):
            # Check it's actually an image (not a video/other)
            ext = os.path.splitext(full_path)[1].lower()
            if ext in (".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tiff", ".tif", ".webp"):
                return full_path
    return ""


def _job_results_to_report_data(job: dict) -> tuple[dict, list]:
    """
    Transform the raw job results dict into the shape expected by
    ReportGenerator  (report_data, files_list).
    """
    results = job.get("results") or {}
    config = job.get("config") or {}

    # ── Per-file rows (flattened across models) ───────────────────────
    file_map: dict[str, dict] = {}  # filename → merged info
    total_threats = 0
    threats_found: list[dict] = []

    for model_key, model_data in results.items():
        if not isinstance(model_data, dict):
            continue
        threats_count = model_data.get("threats", 0)
        total_threats += threats_count

        for detail in model_data.get("details", []):
            fname = detail.get("file", "unknown")
            res = detail.get("result") or {}
            err = detail.get("error")

            if fname not in file_map:
                file_map[fname] = {
                    "file_path": fname,
                    "file_size": res.get("size_bytes", ""),
                    "mime_type": res.get("mime_type", ""),
                    "artifact_count": 0,
                    "risk_level": "LOW",
                }

            entry = file_map[fname]

            # Merge risk upward
            risk = res.get("risk_level", "LOW")
            rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            if rank.get(risk, 0) > rank.get(entry["risk_level"], 0):
                entry["risk_level"] = risk

            # Count entities / detections as artifacts
            entry["artifact_count"] += (
                len(res.get("entities", []))
                + len(res.get("detections", []))
                + len(res.get("yara_matches", []))
                + (1 if res.get("is_malicious") else 0)
                + (1 if res.get("violence_detected") else 0)
                + (1 if res.get("is_deepfake") else 0)
            )

            if not entry["mime_type"] and res.get("mime_type"):
                entry["mime_type"] = res["mime_type"]
            if not entry["file_size"] and res.get("size_bytes"):
                entry["file_size"] = res["size_bytes"]

            # Collect threats
            if res.get("is_malicious"):
                threats_found.append({"source": f"{model_key}/{fname}", "severity": "HIGH",
                                      "description": f"Malware detected: {res.get('threat_label', 'unknown')}"})
            if res.get("violence_detected"):
                threats_found.append({"source": f"{model_key}/{fname}", "severity": "HIGH",
                                      "description": f"Violence detected (score {res.get('violence_score', 0):.2f})"})
            if res.get("is_deepfake"):
                threats_found.append({"source": f"{model_key}/{fname}", "severity": "MEDIUM",
                                      "description": "Deepfake content detected"})
            if risk in ("HIGH", "CRITICAL") and model_key == "text":
                threats_found.append({"source": f"{model_key}/{fname}", "severity": risk,
                                      "description": f"Classified as {res.get('label', '?')} (conf {res.get('confidence', 0):.2f})"})
            if err:
                threats_found.append({"source": f"{model_key}/{fname}", "severity": "LOW",
                                      "description": f"Analysis error: {err}"})

    all_files = list(file_map.values())
    # Only put flagged files (MEDIUM/HIGH/CRITICAL) in the report & PDF
    files_list = [f for f in all_files if f["risk_level"] in ("HIGH", "CRITICAL", "MEDIUM")]

    # ── Determine overall verdict  (use ALL files for stats) ──────────
    risk_breakdown = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_files:
        r = f["risk_level"]
        if r in risk_breakdown:
            risk_breakdown[r] += 1
        elif r == "CRITICAL":
            risk_breakdown["HIGH"] += 1

    if total_threats > 0 or risk_breakdown["HIGH"] > 0:
        verdict = "MALICIOUS"
    elif risk_breakdown["MEDIUM"] > 0:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    confidence = 0.0
    total_files = len(files_list) or 1
    if verdict == "CLEAN":
        confidence = 1.0
    else:
        confidence = (risk_breakdown["HIGH"] * 0.9 + risk_breakdown["MEDIUM"] * 0.6) / total_files
        confidence = min(confidence, 1.0)

    start_str = job.get("startTime", "")
    end_str   = job.get("endTime", "")
    try:
        start_dt = datetime.fromisoformat(start_str) if start_str else None
        end_dt   = datetime.fromisoformat(end_str)   if end_str   else None
        if start_dt and end_dt:
            execution_time = (end_dt - start_dt).total_seconds()
        elif start_dt:
            execution_time = (datetime.utcnow() - start_dt).total_seconds()
        else:
            execution_time = 0.0
    except Exception:
        execution_time = 0.0

    # ── Collect per-file keyword evidence for rich PDF cards ──────────
    evidence_details: list[dict] = []
    for model_key, model_data in results.items():
        if not isinstance(model_data, dict):
            continue
        for detail in model_data.get("details", []):
            fname = detail.get("file", "unknown")
            res = detail.get("result") or {}
            risk = res.get("risk_level", "LOW")
            if risk not in ("HIGH", "CRITICAL", "MEDIUM"):
                continue
            evidence_details.append({
                "file": fname,
                "model": model_key,
                "risk_level": risk,
                "label": res.get("label", ""),
                "confidence": res.get("confidence", 0),
                "critical_keywords": res.get("critical_keywords") or (res.get("content_findings") or {}).get("critical_keywords", []),
                "high_keywords": res.get("high_keywords") or (res.get("content_findings") or {}).get("high_keywords", []),
                "medium_keywords": res.get("medium_keywords") or (res.get("content_findings") or {}).get("medium_keywords", []),
                "summary": res.get("summary", ""),
                "threat_label": res.get("threat_label", ""),
                "is_malicious": res.get("is_malicious", False),
                "is_deepfake": res.get("is_deepfake", False),
                "violence_detected": res.get("violence_detected", False),
                "image_path": _resolve_image_path(model_key, res),
            })

    report_data = {
        "timestamp": datetime.utcnow().isoformat(),
        "verdict": verdict,
        "confidence": round(confidence, 4),
        "total_files": len(all_files),
        "flagged_files": len(files_list),
        "execution_time": round(execution_time, 2),
        "risk_breakdown": risk_breakdown,
        "threats_found": threats_found,
        "evidence_details": evidence_details,
        "evidence_path": config.get("evidencePath", ""),
        "models_used": config.get("selectedModels", []),
    }

    return report_data, files_list


@router.get("/report/{job_id}/pdf", tags=["Forensics"])
async def download_pdf_report(job_id: str):
    """
    Generate and download a professional PDF forensic report for a
    completed analysis job.
    """
    if job_id not in job_cache:
        raise HTTPException(404, f"Job {job_id} not found")

    job = job_cache[job_id]
    if job["status"] != "completed" or not job.get("results"):
        raise HTTPException(400, "Analysis not yet completed")

    try:
        from reporting.generator import ReportGenerator

        report_data, files_list = _job_results_to_report_data(job)

        # Write to in-memory buffer via a temp file (ReportLab needs a path)
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            tmp_path = tmp.name

        generator = ReportGenerator()
        generator.generate(report_data, files_list, tmp_path)

        pdf_bytes = Path(tmp_path).read_bytes()
        os.unlink(tmp_path)

        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="forensic_report_{job_id}.pdf"'
            },
        )
    except ImportError as exc:
        raise HTTPException(500, f"PDF generation unavailable: {exc}")
    except Exception as exc:
        logger.error("PDF report generation failed for job %s: %s", job_id, exc, exc_info=True)
        raise HTTPException(500, f"Report generation failed: {exc}")


@router.get("/report/{job_id}/json", tags=["Forensics"])
async def download_json_report(job_id: str):
    """
    Download a structured JSON forensic report for a completed analysis job.
    Easier to read than the raw status output.
    """
    if job_id not in job_cache:
        raise HTTPException(404, f"Job {job_id} not found")

    job = job_cache[job_id]
    if job["status"] != "completed" or not job.get("results"):
        raise HTTPException(400, "Analysis not yet completed")

    report_data, files_list = _job_results_to_report_data(job)

    structured = {
        "report": report_data,
        "files": files_list,
        "raw_results": job["results"],
    }

    import json
    json_bytes = json.dumps(structured, indent=2, ensure_ascii=False).encode("utf-8")

    return StreamingResponse(
        io.BytesIO(json_bytes),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="forensic_report_{job_id}.json"'
        },
    )


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
