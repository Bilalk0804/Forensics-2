"""File malware scanning service — delegates to MalwareModel."""
import asyncio
import logging
from api.services.model_registry import ModelRegistry

logger = logging.getLogger(__name__)


async def run_malware_scan(data: bytes, filename: str = "") -> dict:
    """
    Run malware analysis (hashing + PE parsing + YARA).

    Returns a dict matching MalwareScanResponse schema:
        is_malicious, confidence, threat_label, threat_family, hashes, pe_info, yara_matches
    """
    model = ModelRegistry.get("malware")
    result = await asyncio.to_thread(model.predict, data)
    result["filename"] = filename
    result["size_bytes"] = len(data)
    return result
