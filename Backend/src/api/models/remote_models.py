"""
Remote inference wrappers — drop-in replacements for local model classes.

These classes send prediction requests to a Kaggle/Colab GPU server running
kaggle_inference_server.ipynb, exposed via ngrok.

HOW TO USE:
  1. Upload kaggle_inference_server.ipynb to https://kaggle.com/code
  2. Add your ngrok auth token as a Kaggle Secret named: NGROK_TOKEN
     (Notebook settings → Secrets → Add New Secret)
  3. Enable GPU: Notebook settings → Accelerator → GPU T4 x2
  4. Run all cells — copy the printed ngrok URL (e.g. https://xxxx.ngrok-free.app)
  5. In your local terminal (or .env file):
       set USE_REMOTE_INFERENCE=true
       set KAGGLE_INFERENCE_URL=https://xxxx.ngrok-free.app
  6. Run: python run_api.py

The local backend will use these lightweight wrappers instead of loading
huge HuggingFace models — startup goes from ~3 min → ~5 sec.
File and Malware models still run locally (no HuggingFace, already fast).
"""

import base64
import logging
import threading
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Import keyword sets for local post-processing on Kaggle results.
# This ensures critical/high/medium keywords are always detected,
# even when the remote server is a model-only endpoint.
try:
    from .text_model import _KW_CRITICAL, _KW_HIGH, _KW_MEDIUM
except ImportError:
    _KW_CRITICAL = _KW_HIGH = _KW_MEDIUM = frozenset()

_TIMEOUT = 120  # seconds per request — increased for parallel GPU inference load

# Shared persistent HTTP client with connection pooling.
# httpx.Client is thread-safe for concurrent requests.
# Limits: max 20 connections total, 10 per host (ngrok free tier allows ~10 simultaneous).
_client_lock = threading.Lock()
_shared_client: httpx.Client | None = None


def _get_client() -> httpx.Client:
    """Return (or lazily create) the shared persistent httpx client."""
    global _shared_client
    if _shared_client is None:
        with _client_lock:
            if _shared_client is None:  # double-checked locking
                _shared_client = httpx.Client(
                    timeout=_TIMEOUT,
                    limits=httpx.Limits(
                        max_connections=20,
                        max_keepalive_connections=10,
                        keepalive_expiry=30,
                    ),
                )
    return _shared_client


def _post(base_url: str, route: str, payload: dict) -> dict:
    """Synchronous POST — uses shared persistent client for connection pooling."""
    url = base_url.rstrip("/") + route
    try:
        r = _get_client().post(url, json=payload)
        r.raise_for_status()
        return r.json()
    except httpx.ConnectError:
        logger.error("Remote inference server unreachable at %s", base_url)
        return None
    except httpx.TimeoutException:
        logger.error("Remote inference timed out (%ss) for %s", _TIMEOUT, route)
        return None
    except Exception as exc:
        logger.error("Remote inference error for %s: %s", route, exc)
        return None


# ─────────────────────────────────────────────────────────────────────────────
class RemoteTextModel:
    """
    Drop-in replacement for TextModel.
    predict(text: str) -> dict
    """
    # Truncate text to avoid sending huge files over ngrok (free tier is throttled).
    # 12,000 chars is ~3x the max BERT context window — plenty for forensic analysis.
    _MAX_CHARS = 12_000

    def __init__(self, base_url: str):
        self._base_url = base_url
        logger.info("✓ RemoteTextModel connected to %s", base_url)

    def predict(self, text: str) -> dict:
        if len(text) > self._MAX_CHARS:
            logger.debug("RemoteTextModel: truncating text from %d to %d chars", len(text), self._MAX_CHARS)
            text = text[:self._MAX_CHARS]
        result = _post(self._base_url, "/predict/text", {"text": text})
        if result is None:
            result = {
                "label": "model-unavailable",
                "confidence": 0.0,
                "tokens_processed": 0,
                "entities": [],
                "summary": "",
                "categories": [],
                "risk_level": "LOW",
                "components_status": {"ner": "unavailable", "summarizer": "unavailable", "classifier": "unavailable"},
                "error": "Remote inference server unreachable",
            }

        # Always run keyword scan locally — Kaggle server is model-only
        t = text.lower()
        critical_kws = sorted({kw for kw in _KW_CRITICAL if kw in t})
        high_kws = sorted({kw for kw in _KW_HIGH if kw in t})
        medium_kws = sorted({kw for kw in _KW_MEDIUM if kw in t})
        result.setdefault("critical_keywords", critical_kws)
        result.setdefault("high_keywords", high_kws)
        result.setdefault("medium_keywords", medium_kws)

        # Re-evaluate risk level to incorporate keyword evidence
        existing_risk = result.get("risk_level", "LOW")
        if critical_kws and existing_risk != "HIGH":
            result["risk_level"] = "HIGH"
        elif high_kws and existing_risk == "LOW":
            result["risk_level"] = "HIGH"
        elif medium_kws and existing_risk == "LOW":
            result["risk_level"] = "MEDIUM"

        return result


# ─────────────────────────────────────────────────────────────────────────────
class RemoteAudioModel:
    """
    Drop-in replacement for AudioModel.
    predict(data: bytes) -> dict
    """
    _MAX_BYTES = 5 * 1024 * 1024  # 5 MB — Whisper-tiny works fine on short clips

    def __init__(self, base_url: str):
        self._base_url = base_url
        logger.info("✓ RemoteAudioModel connected to %s", base_url)

    def predict(self, data: bytes) -> dict:
        if len(data) > self._MAX_BYTES:
            logger.debug("RemoteAudioModel: truncating audio from %d to %d bytes", len(data), self._MAX_BYTES)
            data = data[:self._MAX_BYTES]
        result = _post(
            self._base_url,
            "/predict/audio",
            {"data_b64": base64.b64encode(data).decode()},
        )
        if result is None:
            return {
                "label": "model-unavailable",
                "confidence": 0.0,
                "transcription": "",
                "duration_seconds": 0.0,
                "error": "Remote inference server unreachable",
            }
        return result


# ─────────────────────────────────────────────────────────────────────────────
class RemoteVisionModel:
    """
    Drop-in replacement for VisionModel.
    predict(data: bytes) -> dict
    """
    _MAX_BYTES = 10 * 1024 * 1024  # 10 MB — downsample large images before sending

    def __init__(self, base_url: str):
        self._base_url = base_url
        logger.info("✓ RemoteVisionModel connected to %s", base_url)

    def predict(self, data: bytes) -> dict:
        if len(data) > self._MAX_BYTES:
            try:
                from PIL import Image
                import io
                img = Image.open(io.BytesIO(data)).convert('RGB')
                img.thumbnail((1280, 1280))  # resize keeping aspect ratio
                buf = io.BytesIO()
                img.save(buf, format='JPEG', quality=85)
                data = buf.getvalue()
                logger.debug("RemoteVisionModel: resized image to %d bytes", len(data))
            except Exception:
                data = data[:self._MAX_BYTES]
        result = _post(
            self._base_url,
            "/predict/vision",
            {"data_b64": base64.b64encode(data).decode()},
        )
        if result is None:
            return {
                "label": "model-unavailable",
                "confidence": 0.0,
                "detections": [],
                "violence_detected": False,
                "violence_score": 0.0,
                "risk_level": "LOW",
                "detection_count": 0,
                "summary": "Remote inference unavailable.",
                "error": "Remote inference server unreachable",
            }
        # Apply the same violence threshold used locally — the Kaggle server uses
        # score > 0.5 which causes false positives on face close-ups.
        _REMOTE_VIOLENCE_THRESHOLD = 0.70
        _HIGH_RISK_OBJECTS = {"knife", "scissors", "gun", "rifle", "pistol", "sword"}
        _MED_RISK_OBJECTS = {"person", "car", "truck", "motorcycle", "bus", "cell phone", "laptop", "backpack", "suitcase"}
        v_score = result.get("violence_score", 0.0)
        if result.get("violence_detected") and v_score < _REMOTE_VIOLENCE_THRESHOLD:
            result["violence_detected"] = False
            # Re-derive risk level from detections only
            dets = result.get("detections") or []
            if any(d.get("class_name", "").lower() in _HIGH_RISK_OBJECTS for d in dets):
                result["risk_level"] = "HIGH"
            elif any(d.get("class_name", "").lower() in _MED_RISK_OBJECTS for d in dets):
                result["risk_level"] = "MEDIUM"
            else:
                result["risk_level"] = "LOW"
        elif result.get("violence_detected") and v_score >= _REMOTE_VIOLENCE_THRESHOLD:
            # Tiered: 0.85+ = HIGH, 0.70-0.85 = MEDIUM
            result["risk_level"] = "HIGH" if v_score >= 0.85 else "MEDIUM"

        # Generate summary from remote result if missing
        if "summary" not in result:
            parts = []
            dets = result.get("detections") or []
            if dets:
                obj_counts: dict[str, int] = {}
                for d in dets:
                    n = d.get("class_name", "object")
                    obj_counts[n] = obj_counts.get(n, 0) + 1
                obj_strs = [f"{c} {n}" if c > 1 else n for n, c in obj_counts.items()]
                parts.append(f"Detected {', '.join(obj_strs)}.")
            if result.get("violence_detected"):
                parts.append(f"Violence detected (score {result.get('violence_score', 0):.2f}).")
            result["summary"] = " ".join(parts) if parts else "No significant objects or violence detected."
        return result


# ─────────────────────────────────────────────────────────────────────────────
class RemoteDeepfakeModel:
    """
    Drop-in replacement for DeepfakeModel.
    predict(data: bytes) -> dict
    """
    _MAX_BYTES = 10 * 1024 * 1024  # 10 MB — resize large images before sending

    def __init__(self, base_url: str):
        self._base_url = base_url
        logger.info("✓ RemoteDeepfakeModel connected to %s", base_url)

    def predict(self, data: bytes) -> dict:
        if len(data) > self._MAX_BYTES:
            try:
                from PIL import Image
                import io
                img = Image.open(io.BytesIO(data)).convert('RGB')
                img.thumbnail((1280, 1280))
                buf = io.BytesIO()
                img.save(buf, format='JPEG', quality=85)
                data = buf.getvalue()
                logger.debug("RemoteDeepfakeModel: resized image to %d bytes", len(data))
            except Exception:
                data = data[:self._MAX_BYTES]
        result = _post(
            self._base_url,
            "/predict/deepfake",
            {"data_b64": base64.b64encode(data).decode()},
        )
        if result is None:
            return {
                "is_deepfake": False,
                "confidence": 0.0,
                "label": "model-unavailable",
                "summary": "Remote inference unavailable.",
                "error": "Remote inference server unreachable",
            }
        # Generate summary from remote result if missing
        if "summary" not in result:
            is_df = result.get("is_deepfake", False)
            conf = result.get("confidence", 0)
            verdict = "FAKE (deepfake)" if is_df else "REAL (authentic)"
            result["summary"] = (f"Deepfake probability: {conf * 100:.1f}%. Verdict: {verdict}.")
        return result
