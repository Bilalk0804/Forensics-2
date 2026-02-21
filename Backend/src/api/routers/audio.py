"""Audio analysis router."""
from fastapi import APIRouter, File, UploadFile, HTTPException, status
from api.schemas.audio import AudioAnalyzeResponse
from api.services.audio_service import run_audio_analysis

router = APIRouter()

ALLOWED_TYPES = {"audio/mpeg", "audio/wav", "audio/x-wav", "audio/ogg", "audio/flac", "audio/mp4"}
MAX_SIZE = 100 * 1024 * 1024  # 100 MB


@router.post(
    "/analyze",
    response_model=AudioAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyse an audio file",
)
async def analyze_audio(file: UploadFile = File(..., description="Audio file (MP3/WAV/OGG)")):
    """
    Run audio analysis for forensic investigation.
    
    - Analyzes audio content and characteristics
    - Detects speech and audio patterns
    - Extracts forensic features
    
    Args:
        file: Audio file in MP3, WAV, OGG, FLAC, or MP4 format
        
    Returns:
        Analysis results with confidence and duration
    """
    if file.content_type not in ALLOWED_TYPES:
        raise HTTPException(400, f"Unsupported file type: {file.content_type}")

    data = await file.read()
    if len(data) > MAX_SIZE:
        raise HTTPException(413, "File exceeds 100 MB limit.")

    try:
        result = await run_audio_analysis(data, file.filename or "upload")
        return AudioAnalyzeResponse(**result)
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))
    except Exception as exc:
        raise HTTPException(500, f"Audio analysis error: {exc}")
