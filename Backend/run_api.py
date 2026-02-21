"""Launch FastAPI server with correct Python path."""
import sys
import os

# Add Backend/src to path
backend_src = os.path.join(os.path.dirname(__file__), "src")
sys.path.insert(0, backend_src)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info",
    )
