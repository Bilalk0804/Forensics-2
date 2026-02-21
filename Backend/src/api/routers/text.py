"""Text analysis router."""
from fastapi import APIRouter, HTTPException, status
from api.schemas.text import TextAnalyzeRequest, TextAnalyzeResponse
from api.services.text_service import run_text_analysis

router = APIRouter()


@router.post(
    "/analyze",
    response_model=TextAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyse text with NLP model",
)
async def analyze_text(payload: TextAnalyzeRequest):
    """
    Run NLP inference on raw text for forensic evidence extraction.
    
    - Extracts entities (names, organizations, locations)
    - Analyzes sentiment and communication patterns
    - Detects suspicious content
    
    Returns:
        Classification label, confidence score, and tokens processed
    """
    try:
        result = await run_text_analysis(payload.text)
        return TextAnalyzeResponse(**result)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Text analysis error: {exc}")
