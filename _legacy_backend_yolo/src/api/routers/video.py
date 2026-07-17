"""Video/deepfake detection router."""
from fastapi import APIRouter, File, UploadFile, HTTPException, status
from api.schemas.video import DeepfakeDetectResponse
from api.services.video_service import run_deepfake_detection

router = APIRouter()

ALLOWED_TYPES = {"video/mp4", "video/avi", "video/x-msvideo", "video/quicktime", "video/x-matroska"}
MAX_SIZE = 500 * 1024 * 1024  # 500 MB


@router.post(
    "/deepfake-detect",
    response_model=DeepfakeDetectResponse,
    status_code=status.HTTP_200_OK,
    summary="Detect deepfakes in a video file",
)
async def detect_deepfake(file: UploadFile = File(..., description="Video file (MP4/AVI/MOV)")):
    """
    Run deepfake detection on video for forensic investigation.
    
    - Detects manipulated or synthetic video content
    - Analyzes frame consistency
    - Flags potential deepfakes or edited footage
    
    Args:
        file: Video file in MP4, AVI, MOV, or MKV format
        
    Returns:
        Deepfake detection results with confidence score
    """
    if file.content_type not in ALLOWED_TYPES:
        raise HTTPException(400, f"Unsupported file type: {file.content_type}")

    data = await file.read()
    if len(data) > MAX_SIZE:
        raise HTTPException(413, "File exceeds 500 MB limit.")

    try:
        result = await run_deepfake_detection(data, file.filename or "upload")
        return DeepfakeDetectResponse(**result)
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))
    except Exception as exc:
        raise HTTPException(500, f"Deepfake detection error: {exc}")
