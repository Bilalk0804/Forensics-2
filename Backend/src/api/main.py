"""Main FastAPI application for Sentinel Forensics ML Inference API."""
from contextlib import asynccontextmanager
import logging
import string

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routers import text, image, audio, video, file, forensics, nlp
from api.services.model_registry import ModelRegistry

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(name)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load all forensic ML models at startup, unload at shutdown."""
    logger.info("Loading forensic analysis models...")
    await ModelRegistry.load_all()
    models = ModelRegistry.loaded_models()
    logger.info(f"{len(models)} models ready: {models}")
    yield
    logger.info("Shutting down and unloading models...")
    await ModelRegistry.unload_all()


app = FastAPI(
    title="Sentinel Forensics — AI Analysis API",
    description=(
        "Production-grade REST API for AI-powered digital forensics. "
        "Analyzes images, documents, executables, and multimedia for evidence. "
        "Supports object detection, malware analysis, NLP extraction, and deepfake detection."
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS middleware for cross-origin requests (from React frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Include Routers ────────────────────────────────────────────────────
app.include_router(forensics.router, prefix="/api/master-agent", tags=["Forensics Workflow"])
app.include_router(nlp.router,      prefix="/api/nlp",          tags=["NLP / Evidence"])
app.include_router(text.router,     prefix="/api/text",         tags=["Text / NLP"])
app.include_router(image.router,    prefix="/api/image",        tags=["Image / Vision"])
app.include_router(audio.router,    prefix="/api/audio",        tags=["Audio"])
app.include_router(video.router,    prefix="/api/video",        tags=["Video / Deepfake"])
app.include_router(file.router,     prefix="/api/file",         tags=["File / Malware"])


# ── Health Check ────────────────────────────────────────────────────────
@app.get("/health", tags=["Health"], summary="Service health check")
async def health():
    """
    Check API health and loaded models.

    Returns:
        - status: "ok" if running
        - models_loaded: List of successfully initialized models
    """
    return {
        "status": "ok",
        "models_loaded": ModelRegistry.loaded_models(),
    }


# ── API Info ────────────────────────────────────────────────────────────
@app.get("/", tags=["Info"], summary="API information")
async def root():
    """Get API metadata."""
    return {
        "name": "Sentinel Forensics AI API",
        "version": "2.0.0",
        "description": "Digital forensics analysis with HuggingFace ML models",
        "docs": "/docs",
        "health": "/health",
        "endpoints": {
            "text_analysis":    "/api/text/analyze",
            "image_classify":   "/api/image/classify",
            "malware_scan":     "/api/file/malware-scan",
            "audio_analysis":   "/api/audio/analyze",
            "deepfake_detect":  "/api/video/deepfake-detect",
            "nlp_upload":       "/api/nlp/upload",
            "nlp_analyze":      "/api/nlp/analyze/{jobId}",
            "forensic_models":  "/api/master-agent/models",
            "forensic_analyze": "/api/master-agent/analyze",
        },
    }


# ── Available Drives (for evidence path picker) ────────────────────────
@app.get("/api/drives", tags=["Utility"], summary="List available drives")
async def list_drives():
    """Return available filesystem drives (Windows) or mount points."""
    import os
    import platform

    drives = []
    if platform.system() == "Windows":
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                drives.append(drive)
    else:
        drives = ["/"]
        for mount in ("/home", "/mnt", "/media", "/tmp"):
            if os.path.exists(mount):
                drives.append(mount)

    return {
        "drives": drives,
        "default_path": drives[0] if drives else None,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
        timeout_keep_alive=300,  # 5 min keep-alive for slow HF model inference
    )
