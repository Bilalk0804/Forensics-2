"""Image analysis router."""
from fastapi import APIRouter, File, UploadFile, HTTPException, status
from api.schemas.image import ImageClassifyResponse
from api.services.image_service import run_image_classification

router = APIRouter()

ALLOWED_TYPES = {"image/jpeg", "image/png", "image/webp", "image/bmp", "image/tiff"}
MAX_SIZE = 20 * 1024 * 1024  # 20 MB


@router.post(
    "/classify",
    response_model=ImageClassifyResponse,
    status_code=status.HTTP_200_OK,
    summary="Classify an image with the vision model",
)
async def classify_image(file: UploadFile = File(..., description="Image file (JPEG/PNG/WEBP)")):
    """
    Run vision inference on an image for forensic analysis.
    
    - Detects objects (weapons, contraband, vehicles, people)
    - Analyzes scenes for evidence
    - Extracts visual features for investigation
    
    Args:
        file: Image file in JPEG, PNG, WEBP, BMP, or TIFF format
        
    Returns:
        Classification label, confidence score, and file metadata
    """
    if file.content_type not in ALLOWED_TYPES:
        raise HTTPException(400, f"Unsupported file type: {file.content_type}")

    data = await file.read()
    if len(data) > MAX_SIZE:
        raise HTTPException(413, "File exceeds 20 MB limit.")

    try:
        result = await run_image_classification(data, file.filename or "upload")
        return ImageClassifyResponse(**result)
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))
    except Exception as exc:
        raise HTTPException(500, f"Image analysis error: {exc}")
