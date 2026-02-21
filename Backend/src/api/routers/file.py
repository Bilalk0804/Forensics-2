"""File malware analysis router."""
from fastapi import APIRouter, File, UploadFile, HTTPException, status
from api.schemas.file import MalwareScanResponse
from api.services.file_service import run_malware_scan

router = APIRouter()

MAX_SIZE = 200 * 1024 * 1024  # 200 MB


@router.post(
    "/malware-scan",
    response_model=MalwareScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan a file for malware",
)
async def scan_file(file: UploadFile = File(..., description="Any file for malware analysis")):
    """
    Run malware detection on a file for forensic investigation.
    
    - Analyzes executables for malicious signatures
    - Detects known malware families
    - Extracts threat indicators (IOCs)
    - Calculates file hashes (MD5, SHA1, SHA256)
    
    Args:
        file: Any file to scan for malware
        
    Returns:
        Malware scan results with threat assessment and hashes
    """
    data = await file.read()
    if len(data) > MAX_SIZE:
        raise HTTPException(413, "File exceeds 200 MB limit.")

    try:
        result = await run_malware_scan(data, file.filename or "upload")
        return MalwareScanResponse(**result)
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))
    except Exception as exc:
        raise HTTPException(500, f"Malware scan error: {exc}")
