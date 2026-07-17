# ============================================================================
# Sentinel Forensics Platform - Integrated Docker Image
# Includes: YOLO Vision Detection + Malware Analysis (PE + URL)
# ============================================================================

FROM python:3.10-slim-bullseye

# Set working directory
WORKDIR /app

# Install system dependencies for computer vision and malware analysis
RUN apt-get update && apt-get install -y \
    build-essential \
    libsm6 \
    libxext6 \
    libxrender-dev \
    libgomp1 \
    libopenblas-dev \
    liblapack-dev \
    gfortran \
    git \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt requirements.txt

# Install Python dependencies
# Install in stages to optimize caching
RUN pip3 install --upgrade pip setuptools wheel && \
    pip3 install -r requirements.txt

# Copy entire backend application
COPY . .

# Create output directories
RUN mkdir -p OUTPUT/logs OUTPUT/reports EVIDENCE_LOCKER

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    CUDA_VISIBLE_DEVICES=0

# Expose port for API
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import requests; requests.get('http://localhost:8000/health')" || exit 1

# Default command: Run the FastAPI server
CMD ["python3", "run_api.py"]
