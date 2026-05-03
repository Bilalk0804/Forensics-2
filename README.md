# 🔎 AI-Powered Digital Forensics Engine

> An advanced, GPU-accelerated multimodal forensic intelligence system for analyzing large-scale digital evidence across text, images, audio, video, and executable files.

[![FastAPI](https://img.shields.io/badge/FastAPI-2.0.0-009688?style=flat&logo=fastapi)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.3.1-61DAFB?style=flat&logo=react)](https://reactjs.org/)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.0+-EE4C2C?style=flat&logo=pytorch)](https://pytorch.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
---

## 📋 Table of Contents

- [Project Overview](#-project-overview)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Data Flow](#-data-flow)
- [System Diagrams](#-system-diagrams)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Setup & Installation](#-setup--installation)
- [Usage Guide](#-usage-guide)
- [API Reference](#-api-reference)
- [Design Decisions](#-design-decisions--best-practices)
- [Use Cases](#-use-cases)
- [Disclaimer](#%EF%B8%8F-disclaimer)

---

## 🎯 Project Overview

The **AI-Powered Digital Forensics Engine** is a production-grade forensic analysis platform designed to help investigators, cybersecurity professionals, and researchers process massive volumes of digital evidence efficiently. By leveraging state-of-the-art deep learning models and GPU acceleration, the system can analyze millions of files across multiple modalities, automatically triaging evidence based on risk level and enabling semantic search across entire datasets.

### Objectives

1. **Rapid Evidence Triage**: Automatically classify and prioritize files based on forensic relevance and threat level
2. **Multimodal Analysis**: Process text documents, images, audio, video, and executables using specialized AI models
3. **Semantic Search**: Enable natural language queries across evidence (e.g., "find images with weapons" or "documents about money laundering")
4. **Explainable AI**: Provide transparent reasoning for all risk assessments and threat classifications
5. **Scalable Processing**: Design for datacenter GPUs with batch processing capabilities for large-scale investigations

### Key Features

#### 🧠 **Text & Document Forensics**
- Named Entity Recognition (BERT-based) for extracting people, organizations, locations
- Criminal keyword detection with contextual phrase matching
- AI-powered query rewriting to generate investigative variants and synonyms
- Semantic similarity search using sentence embeddings (384-dimensional)
- Document summarization and intent analysis
- PDF and text file processing

#### 🖼️ **Image & Vision Analysis**
- **Object Detection**: YOLOv8n for detecting 80 COCO classes
- **Violence Detection**: Custom ViT-based model for detecting violent content (threshold: 0.70)
- **Weapon Detection**: CLIP zero-shot classification for firearms and weapons
- **Deepfake Detection**: Vision Transformer-based authenticity verification
- **Face Detection**: MediaPipe face mesh with OpenCV fallback
- **OCR**: EasyOCR for extracting text from images
- **Scene Understanding**: CLIP-based semantic image analysis
- **Cross-modal Search**: Text-to-image retrieval using CLIP embeddings

#### 🦠 **Malware & File Intelligence**
- Machine learning-based malware classification (PE files)
- PE header analysis using `pefile` library
- YARA rule scanning for signature-based detection
- URL malware classification
- File integrity verification and hash analysis
- Duplicate file detection using content hashing and embeddings
- MIME type validation and double-extension detection

#### 🎧 **Audio Analysis**
- Speech-to-text transcription using OpenAI Whisper (tiny model)
- Audio-based keyword detection in transcripts
- Forensic audio feature extraction with Librosa

#### 🔍 **Intelligent Query System**
- **Dynamic Query Rewriting**: LLM-powered expansion of investigative queries
- **Variant Generation**: Creates multiple search angles (synonyms, related terms, investigative expansions)
- **Crime Categorization**: Auto-classifies queries into cybercrime, violent crime, fraud, etc.
- **Analysis Planning**: Generates step-by-step investigation plans based on query intent
- **Max-similarity Scoring**: Ranks results across all query variants

#### 🧩 **Advanced Intelligence Features**
- **Cross-Modal Correlation**: Links related evidence across text, images, and files
- **Evidence Clustering**: Groups related findings using spatial and semantic proximity
- **Explainability Engine**: Provides factor-by-factor reasoning for every risk assessment
- **Feedback Loop**: Collects manual reviews to tune detection thresholds over time
- **Vector Search**: FAISS-powered semantic search with 384-dim text + 512-dim image embeddings
- **Report Generation**: Automated PDF reports with tiered risk assessment

---

## 🏗️ Architecture

The system follows a **microservices-inspired architecture** with a Python backend and React frontend, orchestrated via Docker Compose.

### High-Level Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                         USER INTERFACE LAYER                           │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │         React Frontend (TypeScript + Vite)                       │  │
│  │  • Evidence Path Selection          • Real-time WebSocket        │  │
│  │  • Model Selection Interface        • Results Dashboard          │  │
│  │  • Query Chat Panel                 • Report Viewer              │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
                                    ▲  │
                                    │  │  HTTP/REST + WebSocket
                                    │  ▼
┌────────────────────────────────────────────────────────────────────────┐
│                          API GATEWAY LAYER                             │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │               FastAPI Server (Port 8000)                         │  │
│  │  • CORS Middleware            • Health Check Endpoints           │  │
│  │  • Request Validation         • Model Registry Management        │  │
│  │  • Background Task Queue      • WebSocket Event Broadcasting     │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                      ANALYSIS ORCHESTRATION LAYER                        │
│  ┌──────────────────────┐  ┌──────────────────────┐  ┌────────────────┐ │
│  │ Forensic Orchestrator│  │  Intelligence Engine │  │ Query Rewriter │ │
│  │  • Job Management    │  │  • Query Expansion   │  │ • LLM Variants │ │
│  │  • Pipeline Coord.   │  │  • Policy Loading    │  │ • Crime Categ. │ │
│  │  • Result Aggreg.    │  │  • Crime Analysis    │  │ • Analysis Plan│ │
│  └──────────────────────┘  └──────────────────────┘  └────────────────┘ │
└──────────────────────────────────────────────────────────────────────────┘
                    │
    ┌───────────────┼───────────────────────────┐
    ▼               ▼               ▼           ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     SPECIALIZED ANALYSIS PIPELINES                     │
│  ┌─────────────┐ ┌─────────────┐ ┌──────────────┐ ┌────────────────┐  │
│  │   Vision    │ │    Text     │ │   Malware    │ │   File/Audio   │  │
│  │  Pipeline   │ │  Pipeline   │ │   Pipeline   │ │    Pipelines   │  │
│  │             │ │             │ │              │ │                │  │
│  │ • YOLOv8n   │ │ • BERT NER  │ │ • PE Parser  │ │ • Whisper STT  │  │
│  │ • CLIP      │ │ • DistilBART│ │ • YARA Rules │ │ • MIME Check   │  │
│  │ • Violence  │ │ • Sentence  │ │ • ML Classif.│ │ • Hash Dedup   │  │
│  │   Model     │ │   Transform.│ │ • Docker Scan│ │                │  │
│  │ • Deepfake  │ │ • PyPDF2    │ │              │ │                │  │
│  │ • MediaPipe │ │             │ │              │ │                │  │
│  └─────────────┘ └─────────────┘ └──────────────┘ └────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    INTELLIGENCE & STORAGE LAYER                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌───────────┐  │
│  │ Vector Store │  │   Explainer  │  │  Correlator  │  │ Feedback  │  │
│  │   (FAISS)    │  │  • Factor    │  │  • Cross-    │  │ Collector │  │
│  │ • Text: 384d │  │    Analysis  │  │    Modal     │  │ • Manual  │  │
│  │ • Image:512d │  │  • Risk      │  │    Fusion    │  │   Reviews │  │
│  │              │  │    Breakdown │  │  • Clustering│  │ • Tuning  │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └───────────┘  │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │              OUTPUT / PERSISTENCE                                  │ │
│  │  • SQLite Database (forensics.db)                                  │ │
│  │  • Intelligence JSON (per-job analysis results)                    │ │
│  │  • History JSON (job metadata and summary)                         │ │
│  │  • PDF Reports (executive summaries)                               │ │
│  │  • Vector Index (text.faiss, text_meta.json)                       │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────┘
```

### Component Overview

#### **Backend Components**

| Component | Purpose | Key Technologies |
|-----------|---------|------------------|
| **API Gateway** | REST API and WebSocket server | FastAPI, Uvicorn, Pydantic |
| **Model Registry** | Central GPU model management | PyTorch, CUDA, device_utils |
| **Forensic Orchestrator** | Master analysis coordinator | Threading, asyncio |
| **Asset Analyzer** | File metadata and risk classification | MIME detection, hashing |
| **Vision Pipeline** | Image/video analysis | YOLOv8, CLIP, MediaPipe, EasyOCR |
| **Text Pipeline** | Document NLP processing | BERT, DistilBART, sentence-transformers |
| **Malware Pipeline** | Executable and URL scanning | pefile, YARA, scikit-learn |
| **Query Rewriter** | Intelligent query expansion | Google Gemini, LLaMA |
| **Vector Store** | Semantic embedding search | FAISS, sentence-transformers |
| **Explainability Engine** | Risk factor breakdown | Custom scoring algorithms |
| **Cross-Modal Correlator** | Evidence clustering | Keyword overlap, spatial analysis |
| **Feedback Collector** | Manual review integration | JSON persistence |

#### **Frontend Components**

| Component | Purpose | Key Technologies |
|-----------|---------|------------------|
| **Main Dashboard** | Central UI orchestrator | React, TypeScript, Vite |
| **Drive Picker** | Evidence source selection | Custom file browser API |
| **Model Selection** | AI model configuration | Radix UI, custom hooks |
| **Pipeline Status** | Real-time progress tracking | WebSocket, framer-motion |
| **Threat Ledger** | High-risk findings table | Recharts, Shadcn UI |
| **File Inventory** | Complete file listing | Virtual scrolling |
| **Flagged Images Panel** | Suspicious image viewer | Image thumbnails, risk badges |
| **Query Chat Panel** | Semantic search interface | TanStack Query |
| **Intelligence Panel** | Crime analysis summary | Markdown rendering |
| **Explanation Panel** | AI reasoning viewer | Factor visualization |
| **Evidence Clusters** | Related findings grouper | Graph visualization |

---

## 🔄 Data Flow

The system processes evidence through a multi-stage pipeline:

### End-to-End Analysis Workflow

```
┌──────────────────────────────────────────────────────────────────────┐
│  STAGE 1: Evidence Ingestion                                         │
└──────────────────────────────────────────────────────────────────────┘
                            │
    User selects evidence path (e.g., E:\ USB drive)
    Frontend sends POST /api/master-agent/analyze
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│  STAGE 2: Job Creation & Initialization                              │
└──────────────────────────────────────────────────────────────────────┘
                            │
    • Generate unique Job ID (UUID)
    • Create job cache entry with status="running"
    • Initialize WebSocket event broadcasting
    • Persist job metadata to OUTPUT/history/
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│  STAGE 3: Intelligence & Query Planning                              │
└──────────────────────────────────────────────────────────────────────┘
                            │
    ┌─────────────────────────────────────────┐
    │  IF vision_query or text_query provided │
    │  ┌───────────────────────────────────┐  │
    │  │ 1. Query Rewriter (LLM-based)     │  │
    │  │    • Generate 8 query variants    │  │
    │  │    • Classify crime category      │  │
    │  │    • Create analysis plan         │  │
    │  └───────────────────────────────────┘  │
    │  ┌───────────────────────────────────┐  │
    │  │ 2. Intelligence Engine            │  │
    │  │    • Load policy for crime type   │  │
    │  │    • Set detection thresholds     │  │
    │  │    • Expand query with synonyms   │  │
    │  └───────────────────────────────────┘  │
    └─────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│  STAGE 4: File Discovery & Metadata Extraction                       │
└──────────────────────────────────────────────────────────────────────┘
                            │
    • Recursive directory traversal
    • For each file:
       ┌──────────────────────────────────┐
       │ Asset Analyzer                   │
       │  • Calculate SHA-256 hash        │
       │  • Detect MIME type              │
       │  • Extract metadata (size, etc.) │
       │  • Classify asset type           │
       │  • Initial risk assessment       │
       └──────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│  STAGE 5: Parallel Pipeline Execution                                │
└──────────────────────────────────────────────────────────────────────┘
                            │
    ┌────────────────────────────────────────────────────┐
    │  Route files to specialized pipelines by type:     │
    │                                                     │
    │  ┌──────────────────────────────────────────────┐  │
    │  │  IMAGES → Vision Pipeline                    │  │
    │  │  ┌────────────────────────────────────────┐  │  │
    │  │  │ 1. YOLO Object Detection               │  │  │
    │  │  │    • Detect objects in scene           │  │  │
    │  │  │    • Filter for weapons, persons       │  │  │
    │  │  ├────────────────────────────────────────┤  │  │
    │  │  │ 2. CLIP Semantic Analysis              │  │  │
    │  │  │    • Generate image embedding (512d)   │  │  │
    │  │  │    • Compare with query variants       │  │  │
    │  │  │    • Zero-shot weapon classification   │  │  │
    │  │  ├────────────────────────────────────────┤  │  │
    │  │  │ 3. Violence Detection Model            │  │  │
    │  │  │    • Score: 0-1 probability            │  │  │
    │  │  │    • Threshold: 0.70 (HIGH risk)       │  │  │
    │  │  ├────────────────────────────────────────┤  │  │
    │  │  │ 4. Face Detection (MediaPipe)          │  │  │
    │  │  │    • Count faces in frame              │  │  │
    │  │  ├────────────────────────────────────────┤  │  │
    │  │  │ 5. OCR Text Extraction (EasyOCR)       │  │  │
    │  │  │    • Extract visible text              │  │  │
    │  │  │    • Feed to text pipeline for NLP     │  │  │
    │  │  └────────────────────────────────────────┘  │  │
    │  └──────────────────────────────────────────────┘  │
    │                                                     │
    │  ┌──────────────────────────────────────────────┐  │
    │  │  TEXT/DOCS → Text Pipeline                   │  │
    │  │  ┌────────────────────────────────────────┐  │  │
    │  │  │ 1. BERT Named Entity Recognition       │  │  │
    │  │  │    • Extract: PERSON, ORG, LOC, etc.   │  │  │
    │  │  ├────────────────────────────────────────┤  │  │
    │  │  │ 2. Criminal Keyword Detection          │  │  │
    │  │  │    • Match against crime lexicon       │  │  │
    │  │  │    • Context-aware phrase matching     │  │  │
    │  │  ├────────────────────────────────────────┤  │  │
    │  │  │ 3. Sentence Embedding (MiniLM)         │  │  │
    │  │  │    • Generate 384-dim embedding        │  │  │
    │  │  │    • Index in FAISS vector store       │  │  │
    │  │  ├────────────────────────────────────────┤  │  │
    │  │  │ 4. Semantic Query Matching             │  │  │
    │  │  │    • Compare with query variants       │  │  │
    │  │  │    • Score by cosine similarity        │  │  │
    │  │  ├────────────────────────────────────────┤  │  │
    │  │  │ 5. Document Summarization (DistilBART) │  │  │
    │  │  │    • Generate concise summaries        │  │  │
    │  │  └────────────────────────────────────────┘  │  │
    │  └──────────────────────────────────────────────┘  │
    │                                                     │
    │  ┌──────────────────────────────────────────────┐  │
    │  │  EXECUTABLES → Malware Pipeline              │  │
    │  │  ┌────────────────────────────────────────┐  │  │
    │  │  │ 1. PE Header Analysis (pefile)         │  │  │
    │  │  │    • Extract imports, sections, etc.   │  │  │
    │  │  ├────────────────────────────────────────┤  │  │
    │  │  │ 2. YARA Rule Scanning                  │  │  │
    │  │  │    • Match signature database          │  │  │
    │  │  ├────────────────────────────────────────┤  │  │
    │  │  │ 3. ML Malware Classifier               │  │  │
    │  │  │    • Feature vector extraction         │  │  │
    │  │  │    • Predict: benign/malicious         │  │  │
    │  │  ├────────────────────────────────────────┤  │  │
    │  │  │ 4. Docker Sandbox (optional)           │  │  │
    │  │  │    • Isolated dynamic analysis         │  │  │
    │  │  └────────────────────────────────────────┘  │  │
    │  └──────────────────────────────────────────────┘  │
    │                                                     │
    │  ┌──────────────────────────────────────────────┐  │
    │  │  AUDIO → Audio Pipeline                      │  │
    │  │  • Whisper transcription → text pipeline     │  │
    │  │  • Keyword detection in transcript           │  │
    │  └──────────────────────────────────────────────┘  │
    └─────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│  STAGE 6: Advanced Intelligence Processing                           │
└──────────────────────────────────────────────────────────────────────┘
    │
    ├─→ Explainability Engine
    │   • Break down risk scores into contributing factors
    │   • Identify top 10 factors per file
    │   • Generate human-readable explanations
    │
    ├─→ Cross-Modal Correlator
    │   • Find related evidence across modalities
    │   • Group by keywords, spatial proximity, temporal patterns
    │   • Create evidence clusters
    │
    ├─→ Vector Store Indexing
    │   • Add all embeddings to FAISS index
    │   • Enable semantic search post-analysis
    │
    └─→ Feedback Collector
        • Store analysis results for tuning
        • Learn from manual reviews
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│  STAGE 7: Result Aggregation & Reporting                             │
└──────────────────────────────────────────────────────────────────────┘
                            │
    • Aggregate findings from all pipelines
    • Calculate overall risk scores
    • Generate recommendations
    • Create PDF report with:
       - Executive Summary
       - High-Risk Findings (score ≥ 0.70)
       - Medium-Risk Findings (0.40-0.69)
       - Statistics and charts
    • Persist to OUTPUT/intelligence/{job_id}.json
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│  STAGE 8: Results Delivery                                           │
└──────────────────────────────────────────────────────────────────────┘
    │
    • Stream real-time updates via WebSocket
    • Update job status to "completed"
    • Frontend displays:
       - Threat Ledger (high-risk items)
       - File Inventory (all processed files)
       - Flagged Images (suspicious visual content)
       - Intelligence Summary (AI-generated)
       - Explanation Factors
       - Evidence Clusters
       - Vector Search Panel
```

### Pipeline Selection Logic

The system intelligently routes files to appropriate analysis pipelines based on MIME type and file extensions:

```python
# Asset Type → Recommended Pipelines
IMAGE_TYPES     → [vision_pipeline, text_pipeline (OCR)]
TEXT_TYPES      → [text_pipeline]
EXECUTABLE_TYPES → [malware_pipeline, file_pipeline]
AUDIO_TYPES     → [audio_pipeline, text_pipeline (transcription)]
VIDEO_TYPES     → [vision_pipeline, deepfake_pipeline]
DOCUMENT_TYPES  → [text_pipeline]
ARCHIVE_TYPES   → [file_pipeline]
UNKNOWN_TYPES   → [file_pipeline]
```

---

## 📊 System Diagrams

### Request-Response Flow (POST /api/master-agent/analyze)

```
┌─────────┐                                              ┌────────────┐
│ Browser │                                              │  FastAPI   │
│ (React) │                                              │   Server   │
└────┬────┘                                              └─────┬──────┘
     │                                                          │
     │  1. POST /api/master-agent/analyze                      │
     │     {                                                    │
     │       evidencePath: "E:/",                               │
     │       selectedModels: ["vision", "text", "malware"],     │
     │       visionQuery: "weapons",                            │
     │       textQuery: "threats"                               │
     │     }                                                    │
     ├─────────────────────────────────────────────────────────▶│
     │                                                          │
     │                                          2. Create job_id (UUID)
     │                                             job_cache[job_id] = {
     │                                               status: "queued",
     │                                               progress: 0
     │                                             }
     │                                                          │
     │  3. Return job_id immediately                            │
     │     { jobId: "7c44e929-..." }                            │
     │◀─────────────────────────────────────────────────────────┤
     │                                                          │
     │                                          4. Start background task
     │                                             _run_forensic_job()
     │                                                          │
     │  5. Establish WebSocket connection                       │
     │     WS /api/master-agent/ws/{job_id}                     │
     ├─────────────────────────────────────────────────────────▶│
     │                                                          │
     │                                          ┌───────────────▼────────┐
     │                                          │  Background Thread     │
     │                                          │  ────────────────────  │
     │                                          │  • File discovery      │
     │                                          │  • Asset analysis      │
     │                                          │  • Pipeline execution  │
     │                                          │  • Real-time events    │
     │                                          └───────────────┬────────┘
     │                                                          │
     │  6. Stream real-time events via WebSocket                │
     │     ┌────────────────────────────────────┐               │
     │     │ • progress_update                  │               │
     │     │ • file_processed                   │               │
     │     │ • model_result                     │               │
     │     │ • image_flagged (with thumbnail)   │               │
     │     │ • log_entry                        │               │
     │     │ • eta_update                       │               │
     │     └────────────────────────────────────┘               │
     │◀──────────────────────────────────────────────────────────┤
     │  (continuous stream)                                     │
     │                                                          │
     │                                                          │
     │  7. Analysis completes                                   │
     │     { event: "job_complete", intelligence: {...} }       │
     │◀─────────────────────────────────────────────────────────┤
     │                                                          │
     │  8. GET /api/master-agent/intelligence/{job_id}          │
     ├─────────────────────────────────────────────────────────▶│
     │                                                          │
     │  9. Return full intelligence report                      │
     │     {                                                    │
     │       summary: "...",                                    │
     │       risk_assessment: {...},                            │
     │       findings: [...],                                   │
     │       clusters: [...],                                   │
     │       explanations: [...]                                │
     │     }                                                    │
     │◀─────────────────────────────────────────────────────────┤
     │                                                          │
     │  10. GET /api/master-agent/report/{job_id}               │
     ├─────────────────────────────────────────────────────────▶│
     │                                                          │
     │  11. Return PDF report (binary)                          │
     │◀─────────────────────────────────────────────────────────┤
     │                                                          │
```

### Model Loading & GPU Management

```
┌──────────────────────────────────────────────────────────────────────┐
│  Application Startup (FastAPI lifespan event)                        │
└──────────────────────────────────────────────────────────────────────┘
                            │
                            ▼
                ┌───────────────────────┐
                │   ModelRegistry       │
                │   load_all()          │
                └───────┬───────────────┘
                        │
        ┌───────────────┼───────────────┬───────────────┐
        ▼               ▼               ▼               ▼
   ┌────────┐     ┌─────────┐    ┌──────────┐    ┌──────────┐
   │  CLIP  │     │  BERT   │    │  Whisper │    │ Violence │
   │  Model │     │   NER   │    │   (STT)  │    │  Detect  │
   └────────┘     └─────────┘    └──────────┘    └──────────┘
       │               │               │               │
       └───────────────┴───────────────┴───────────────┘
                        │
            All models loaded to GPU (CUDA)
            Shared device: torch.device("cuda:0")
                        │
                        ▼
        Models cached in ModelRegistry._models dict
        Available via ModelRegistry.get("clip"), etc.
                        │
                        ▼
        ┌─────────────────────────────────────────┐
        │  On-Demand Loading for Heavy Models:    │
        │  • YOLOv8n (loaded per-request)          │
        │  • Malware classifiers (loaded lazily)  │
        │  • Deepfake detector (on-demand)        │
        └─────────────────────────────────────────┘
```

### Vector Search Flow

```
POST /api/master-agent/analyze
     │
     ▼
┌─────────────────────────────────────────────────┐
│  During Analysis: Embedding Generation          │
├─────────────────────────────────────────────────┤
│  Text Files:                                    │
│    • SentenceTransformer("all-MiniLM-L6-v2")   │
│    • Output: 384-dimensional vector            │
│                                                 │
│  Images:                                        │
│    • CLIP ViT-B/32 image encoder               │
│    • Output: 512-dimensional vector            │
└─────────────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────┐
│  FAISS Indexing (ForensicVectorStore)          │
├─────────────────────────────────────────────────┤
│  • Store text embeddings in IndexFlatL2         │
│  • Store image embeddings separately            │
│  • Metadata: file_path, content, timestamp     │
│  • Persist to OUTPUT/vector_index/             │
│    - text.faiss                                 │
│    - text_meta.json                             │
└─────────────────────────────────────────────────┘
     │
     ▼
POST /api/master-agent/vector-search
     query: "money laundering"
     │
     ▼
┌─────────────────────────────────────────────────┐
│  Query Processing                               │
├─────────────────────────────────────────────────┤
│  1. Encode query → 384-dim vector (text)        │
│  2. FAISS similarity search (k=50)              │
│  3. Rank by L2 distance                         │
│  4. Return top-k results with metadata          │
└─────────────────────────────────────────────────┘
     │
     ▼
Response: [
  {file: "doc.txt", score: 0.92, excerpt: "..."},
  {file: "email.pdf", score: 0.87, excerpt: "..."},
  ...
]
```

---

## 🛠️ Tech Stack

### Backend (Python)

| Category | Technologies |
|----------|-------------|
| **Framework** | FastAPI 0.110+, Uvicorn (ASGI server) |
| **Deep Learning** | PyTorch 2.0+, torchvision, CUDA 11.7+ |
| **Vision Models** | YOLOv8 (Ultralytics), CLIP (OpenAI), MediaPipe, EasyOCR, Custom Violence Detection ViT |
| **NLP Models** | BERT (HuggingFace), DistilBART, Sentence-Transformers (all-MiniLM-L6-v2) |
| **Audio Models** | Whisper (tiny), Librosa, Soundfile |
| **LLM Agents** | Google Gemini API, LLaMA-cpp-python (optional local) |
| **Malware Analysis** | pefile, YARA-python, scikit-learn, joblib |
| **Vector Search** | FAISS (CPU), sentence-transformers |
| **Data Processing** | NumPy, Pillow, OpenCV, PyPDF2 |
| **Monitoring** | psutil, GPUtil, python-dotenv |
| **Reporting** | ReportLab (PDF generation) |
| **Async & Concurrency** | asyncio, threading, BackgroundTasks |

### Frontend (TypeScript/React)

| Category | Technologies |
|----------|-------------|
| **Framework** | React 18.3.1, TypeScript 5.8.3, Vite 7.3.1 |
| **UI Library** | Shadcn UI, Radix UI primitives (30+ components) |
| **State Management** | TanStack Query 5.83 (React Query), React Hooks |
| **Routing** | React Router DOM 6.30 |
| **Animations** | Framer Motion 12.34, Tailwind CSS Animate |
| **Charts & Viz** | Recharts 2.15 (line, bar, pie charts) |
| **Forms** | React Hook Form 7.61, Zod 3.25 (validation) |
| **Styling** | Tailwind CSS 3.4, PostCSS, Autoprefixer |
| **Icons** | Lucide React 0.462 |
| **Date Handling** | date-fns 3.6 |
| **Notifications** | Sonner (toast notifications) |
| **Dev Tools** | ESLint, Vitest, Testing Library |

### Infrastructure & DevOps

- **Containerization**: Docker, Docker Compose
- **GPU Support**: NVIDIA CUDA (nvidia-docker runtime)
- **Version Control**: Git, GitHub
- **Package Management**: pip (Python), npm (Node.js)

---

## 📁 Project Structure

```
Digital_Forensics/
│
├── Backend/                          # Python FastAPI server + ML models
│   ├── src/
│   │   ├── api/                      # FastAPI application
│   │   │   ├── main.py               # API entry point, router setup
│   │   │   ├── routers/              # Endpoint routers
│   │   │   │   ├── forensics.py      # Main workflow (master-agent)
│   │   │   │   ├── text.py           # Text analysis endpoints
│   │   │   │   ├── image.py          # Image analysis endpoints
│   │   │   │   ├── audio.py          # Audio analysis endpoints
│   │   │   │   ├── video.py          # Video/deepfake endpoints
│   │   │   │   ├── file.py           # File/malware endpoints
│   │   │   │   ├── nlp.py            # NLP/evidence endpoints
│   │   │   │   └── browse.py         # File browser utilities
│   │   │   ├── models/               # Pydantic models & utilities
│   │   │   │   ├── device_utils.py   # CUDA device management
│   │   │   │   └── intelligence_engine.py  # Query expansion
│   │   │   ├── services/             # Business logic services
│   │   │   │   └── model_registry.py # Central GPU model manager
│   │   │   └── schemas/              # Request/response schemas
│   │   │
│   │   ├── analyzers/                # Core analysis pipelines
│   │   │   ├── orchestrator.py       # Master analysis coordinator
│   │   │   ├── asset_analyzer.py     # File metadata & risk classifier
│   │   │   ├── text_pipeline.py      # NLP + text analysis
│   │   │   ├── vision_pipeline.py    # Image + video analysis
│   │   │   ├── malware_pipeline.py   # Malware detection
│   │   │   ├── file_pipeline.py      # Generic file analysis
│   │   │   ├── master_agent_pipeline.py  # LLM agent orchestration
│   │   │   ├── query_orchestrator.py # Query-driven analysis
│   │   │   ├── summarization_agent.py # AI summarization (Gemini)
│   │   │   ├── model_manager.py      # Legacy model manager
│   │   │   └── nlp/                  # NLP sub-modules
│   │   │       ├── entity_extractor.py
│   │   │       ├── keyword_matcher.py
│   │   │       └── summarizer.py
│   │   │
│   │   ├── query_engine/             # Intelligent query system
│   │   │   └── rewriter.py           # LLM query expansion & planning
│   │   │
│   │   ├── explainability/           # AI explainability
│   │   │   └── explainer.py          # Risk factor breakdown
│   │   │
│   │   ├── fusion/                   # Cross-modal correlation
│   │   │   └── correlator.py         # Evidence clustering
│   │   │
│   │   ├── feedback/                 # Manual review feedback
│   │   │   └── collector.py          # Feedback persistence & tuning
│   │   │
│   │   ├── vector_store/             # Semantic search
│   │   │   └── faiss_store.py        # FAISS vector indexing
│   │   │
│   │   ├── reporting/                # Report generation
│   │   │   └── pdf_generator.py      # PDF report creation
│   │   │
│   │   ├── core/                     # Core utilities
│   │   │   ├── ingestion.py          # File walking & hashing
│   │   │   ├── usb_detector.py       # Drive detection (Windows)
│   │   │   ├── docker_runner.py      # Docker sandbox execution
│   │   │   ├── model_detector.py     # Model file auto-detection
│   │   │   └── utils.py
│   │   │
│   │   ├── db/                       # Database layer (SQLite)
│   │   │   └── handler.py
│   │   │
│   │   └── config.py                 # Configuration & environment
│   │
│   ├── MODELS/                       # Pre-trained model files
│   │   ├── vision/
│   │   │   ├── best_lstm_model_final.keras  # YOLO/violence models
│   │   │   └── Image/
│   │   │       └── best_violence_model.pth  # Violence detection
│   │   ├── malware_detection/
│   │   │   └── Classifier/
│   │   │       ├── classifier.pkl
│   │   │       ├── pickel_model.pkl
│   │   │       └── pickel_vector.pkl
│   │   └── yara_rules/               # YARA signature database
│   │
│   ├── OUTPUT/                       # Analysis results & artifacts
│   │   ├── intelligence/             # JSON intelligence reports (per-job)
│   │   ├── history/                  # Job metadata & summaries
│   │   ├── vector_index/             # FAISS index files
│   │   ├── feedback/                 # Manual review data
│   │   ├── reports/                  # Generated PDF reports
│   │   └── logs/                     # System logs
│   │
│   ├── EVIDENCE_LOCKER/              # Evidence input directory (mount point)
│   │
│   ├── requirements.txt              # Python dependencies
│   ├── Dockerfile                    # Backend container definition
│   ├── run_api.py                    # API server launcher
│   ├── yolov8n.pt                    # YOLOv8 nano weights
│   └── kaggle_inference_server.ipynb # Remote GPU inference notebook
│
├── Frontend/                         # React TypeScript UI
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Index.tsx             # Main dashboard page (2,000+ lines)
│   │   │   └── NotFound.tsx
│   │   │
│   │   ├── components/
│   │   │   ├── forensics/            # Forensics-specific components
│   │   │   │   ├── Header.tsx
│   │   │   │   ├── DrivePicker.tsx   # Evidence path selector
│   │   │   │   ├── ModelSelection.tsx # AI model config
│   │   │   │   ├── AnalysisPresets.tsx # Pre-configured analysis modes
│   │   │   │   ├── PipelineStatus.tsx # Real-time progress
│   │   │   │   ├── ThreatLedger.tsx  # High-risk findings table
│   │   │   │   ├── FileInventory.tsx # All processed files
│   │   │   │   ├── FlaggedImagesPanel.tsx # Suspicious images
│   │   │   │   ├── SuggestedImagesPanel.tsx # Query-matched images
│   │   │   │   ├── IntelligencePanel.tsx # AI summary
│   │   │   │   ├── ManualReviewPanel.tsx # Human review interface
│   │   │   │   ├── ExplanationPanel.tsx # Risk factor viewer
│   │   │   │   ├── EvidenceClusters.tsx # Related evidence groups
│   │   │   │   ├── VectorSearchPanel.tsx # Semantic search UI
│   │   │   │   ├── QueryChatPanel.tsx # Query input interface
│   │   │   │   ├── AnalysisPlanView.tsx # LLM analysis plan
│   │   │   │   ├── LiveAnalysisStream.tsx # Real-time file stream
│   │   │   │   ├── SkippedFilesPanel.tsx # Files not analyzed
│   │   │   │   ├── AISummaryCard.tsx # Gemini summary
│   │   │   │   ├── AnalysisLogStream.tsx # Log viewer
│   │   │   │   └── ... (20+ components)
│   │   │   └── ui/                   # Shadcn UI primitives
│   │   │
│   │   ├── hooks/
│   │   │   └── useForensicsApi.ts    # API integration hooks
│   │   │
│   │   ├── lib/
│   │   │   ├── api.ts                # Backend API client
│   │   │   ├── masterAgentAPI.ts     # Master agent API wrapper
│   │   │   └── utils.ts              # Utilities
│   │   │
│   │   ├── App.tsx                   # Root app component
│   │   ├── main.tsx                  # Vite entry point
│   │   └── index.css                 # Global styles
│   │
│   ├── public/                       # Static assets
│   ├── package.json                  # Node.js dependencies
│   ├── tsconfig.json                 # TypeScript configuration
│   ├── vite.config.ts                # Vite bundler config
│   ├── tailwind.config.ts            # Tailwind CSS config
│   └── Dockerfile                    # Frontend container definition
│
├── docker-compose.yml                # Orchestrates backend + frontend
├── .gitignore
└── README.md                         # This file
```

### Directory Roles

| Directory | Purpose |
|-----------|---------|
| `Backend/src/api/` | FastAPI REST API and WebSocket server |
| `Backend/src/analyzers/` | Core forensic analysis pipelines |
| `Backend/src/query_engine/` | Intelligent query expansion and planning |
| `Backend/src/explainability/` | AI reasoning transparency |
| `Backend/src/fusion/` | Cross-modal evidence correlation |
| `Backend/src/feedback/` | Manual review integration for model tuning |
| `Backend/src/vector_store/` | FAISS-based semantic search |
| `Backend/src/reporting/` | PDF report generation |
| `Backend/MODELS/` | Pre-trained model files (not in git) |
| `Backend/OUTPUT/` | Analysis results, reports, logs, vector indices |
| `Backend/EVIDENCE_LOCKER/` | Evidence input directory (mount point) |
| `Frontend/src/pages/` | React page components |
| `Frontend/src/components/forensics/` | Domain-specific UI components |
| `Frontend/src/lib/` | API clients and utilities |

---

## ⚙️ Setup & Installation

### Prerequisites

- **Python**: 3.10 or higher
- **Node.js**: 18.x or higher
- **CUDA**: 11.7+ (for GPU acceleration) - optional but highly recommended
- **Docker**: 24.0+ (for containerized deployment) - optional
- **NVIDIA GPU**: Recommended for production use (e.g., RTX 3090, A100, L4)
- **RAM**: Minimum 16GB, recommended 32GB+
- **Storage**: 50GB+ for models and processed evidence

### Option 1: Local Development Setup

#### Backend Setup

```bash
# 1. Clone the repository
git clone https://github.com/your-username/Digital_Forensics.git
cd Digital_Forensics/Backend

# 2. Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Configure environment variables
cp .env.example .env
# Edit .env and add your API keys:
#   GOOGLE_API_KEY=your_gemini_api_key
#   VIRUSTOTAL_API_KEY=your_vt_api_key (optional)
#   OPENAI_API_KEY=your_openai_key (optional)

# 5. Download model files (not included in repo due to size)
# Place models in Backend/MODELS/ directory:
#   - MODELS/vision/yolov8n.pt
#   - MODELS/vision/Image/best_violence_model.pth
#   - MODELS/malware_detection/Classifier/*.pkl
# Models will be auto-downloaded on first run from HuggingFace

# 6. Create output directories
mkdir -p OUTPUT/intelligence OUTPUT/history OUTPUT/vector_index OUTPUT/reports OUTPUT/logs OUTPUT/feedback

# 7. Launch the API server
python run_api.py
# Server will start at http://localhost:8000
# API docs available at http://localhost:8000/docs
```

#### Frontend Setup

```bash
# 1. Navigate to Frontend directory
cd ../Frontend

# 2. Install Node.js dependencies
npm install

# 3. Configure environment (if needed)
# Create .env.local file:
echo "VITE_API_URL=http://localhost:8000" > .env.local

# 4. Start development server
npm run dev
# Frontend will start at http://localhost:5173
```

### Option 2: Docker Deployment (Recommended for Production)

```bash
# 1. Ensure Docker and Docker Compose are installed
docker --version
docker-compose --version

# 2. Build and launch all services
docker-compose up --build

# Services will be available at:
#   - Backend API: http://localhost:8000
#   - Frontend UI: http://localhost:5173
#   - API Docs: http://localhost:8000/docs

# 3. For GPU support, ensure nvidia-docker runtime is installed
docker run --rm --gpus all nvidia/cuda:11.7.1-base-ubuntu22.04 nvidia-smi
```

### Verifying Installation

```bash
# Check backend health
curl http://localhost:8000/health
# Expected: {"status": "ok", "models_loaded": ["clip", "bert_ner", ...]}

# Check available drives (for evidence selection)
curl http://localhost:8000/api/drives
# Expected: {"drives": ["C:\\", "D:\\", ...], "default_path": "C:\\"}

# Check loaded models
curl http://localhost:8000/api/master-agent/models
# Expected: List of available AI models with metadata
```

---

## 🚀 Usage Guide

### Web Interface (Recommended)

The primary way to interact with the system is through the React-based web dashboard:

1. **Open the frontend**: Navigate to `http://localhost:5173`

2. **Select Evidence Source**:
   - Click "Select Evidence Path"
   - Choose a drive or folder to analyze (e.g., `E:\` for USB drive)

3. **Configure AI Models**:
   - Select which models to run:
     - **Vision**: Object detection, violence detection, weapon detection
     - **Text**: NLP, keyword matching, entity extraction
     - **Malware**: PE analysis, YARA scanning, ML classification
     - **File**: MIME validation, integrity checks
     - **Audio**: Speech-to-text, keyword detection
     - **Deepfake**: Video authenticity verification
   - Or choose a preset:
     - **Quick Scan**: Fast triage (file + text only)
     - **Standard Scan**: Balanced analysis (vision + text + file)
     - **Deep Scan**: Comprehensive analysis (all models)
     - **Malware Focus**: Security-focused (malware + file + YARA)

4. **Optional: Add Search Queries**:
   - **Vision Query**: Natural language image search (e.g., "people holding weapons", "violence")
   - **Text Query**: Semantic document search (e.g., "money laundering", "threats")
   - Queries are expanded by the LLM into multiple variants for maximum recall

5. **Launch Analysis**:
   - Click "Start Analysis"
   - Real-time updates stream via WebSocket:
     - Files processed counter
     - Current file and model
     - ETA estimation
     - Flagged threats (live)
   - Analysis results updated continuously

6. **Review Results**:
   - **Threat Ledger**: High-risk findings with confidence scores
   - **Flagged Images**: Visual content requiring review
   - **Intelligence Summary**: AI-generated case overview
   - **Risk Breakdown**: Factors contributing to each file's score
   - **Evidence Clusters**: Related files grouped by keywords/location
   - **Vector Search**: Semantic search across analyzed content

7. **Download Reports**:
   - Click "Download PDF Report" for executive summary
   - Report includes:
     - Case metadata (date, evidence path, models used)
     - Risk tier breakdown (High ≥0.70, Medium 0.40-0.69, Low <0.40)
     - Top findings with explanations
     - Statistics and charts

### API Usage (Programmatic Access)

#### Starting an Analysis Job

```bash
curl -X POST "http://localhost:8000/api/master-agent/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "evidencePath": "E:/",
    "selectedModels": ["vision", "text", "malware"],
    "visionQuery": "weapons or violence",
    "textQuery": "threats or criminal activity"
  }'

# Response:
# {
#   "jobId": "7c44e929-7154-49f7-b3a9-b4d1e2ea645a",
#   "status": "queued"
# }
```

#### Checking Job Status

```bash
curl "http://localhost:8000/api/master-agent/status/7c44e929-7154-49f7-b3a9-b4d1e2ea645a"

# Response:
# {
#   "jobId": "7c44e929-...",
#   "status": "running",
#   "progress": 0.45,
#   "filesProcessed": 128,
#   "totalFiles": 284,
#   "currentFile": "evidence/photo_001.jpg",
#   "currentModel": "vision",
#   "eta": "00:03:42"
# }
```

#### Retrieving Intelligence Report

```bash
curl "http://localhost:8000/api/master-agent/intelligence/7c44e929-7154-49f7-b3a9-b4d1e2ea645a" \
  -o intelligence_report.json

# Contains:
# - summary: AI-generated case summary
# - risk_assessment: Overall risk statistics
# - findings: Detailed per-file analysis results
# - clusters: Related evidence groups
# - explanations: Risk factor breakdowns
```

#### Downloading PDF Report

```bash
curl "http://localhost:8000/api/master-agent/report/7c44e929-7154-49f7-b3a9-b4d1e2ea645a" \
  -o forensic_report.pdf
```

#### Semantic Vector Search

```bash
# After analysis completes, search the vector index
curl -X POST "http://localhost:8000/api/master-agent/vector-search" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "financial fraud or money laundering",
    "top_k": 20,
    "threshold": 0.5
  }'

# Response:
# [
#   {
#     "file_path": "evidence/documents/transactions.pdf",
#     "score": 0.89,
#     "excerpt": "...wire transfer to offshore account...",
#     "modality": "text"
#   },
#   ...
# ]
```

### Analysis Presets

The system includes pre-configured analysis modes for common scenarios:

| Preset | Models | Use Case | Speed |
|--------|--------|----------|-------|
| **Quick Scan** | file, text | Fast triage, initial assessment | ⚡⚡⚡ Very Fast |
| **Standard Scan** | vision, text, file | Balanced general-purpose analysis | ⚡⚡ Fast |
| **Deep Scan** | All models | Comprehensive forensic examination | ⚡ Slow |
| **Malware Focus** | malware, file, YARA | Security-focused executable analysis | ⚡⚡ Fast |
| **Media Investigation** | vision, deepfake, audio | Multimedia evidence processing | ⚡ Slow |

---

## 🔌 API Reference

### Core Endpoints

#### **Health & Information**

- `GET /health` - Service health check
- `GET /` - API metadata and endpoint list
- `GET /docs` - Swagger/OpenAPI documentation
- `GET /api/drives` - List available filesystem drives

#### **Master Agent Workflow**

- `POST /api/master-agent/analyze` - Start forensic analysis job
  - Body: `{evidencePath, selectedModels, visionQuery?, textQuery?}`
  - Returns: `{jobId, status}`

- `GET /api/master-agent/status/{jobId}` - Get job status
  - Returns: `{jobId, status, progress, filesProcessed, currentFile, eta}`

- `GET /api/master-agent/intelligence/{jobId}` - Get intelligence report (JSON)
  - Returns: Full analysis results with findings, clusters, explanations

- `GET /api/master-agent/report/{jobId}` - Download PDF report
  - Returns: Binary PDF file

- `POST /api/master-agent/pause/{jobId}` - Pause running job

- `POST /api/master-agent/resume/{jobId}` - Resume paused job

- `GET /api/master-agent/models` - List available AI models

- `POST /api/master-agent/vector-search` - Semantic search
  - Body: `{query, top_k?, threshold?}`
  - Returns: Array of matching files with scores

- `POST /api/master-agent/feedback` - Submit manual review
  - Body: `{jobId, fileHash, isRelevant, notes?}`

- `GET /api/master-agent/explanation/{jobId}/{fileHash}` - Get risk explanation
  - Returns: Factor-by-factor breakdown

- `GET /api/master-agent/clusters/{jobId}` - Get evidence clusters
  - Returns: Groups of related files

- `WS /api/master-agent/ws/{jobId}` - WebSocket for real-time events
  - Events: `progress_update`, `file_processed`, `model_result`, `image_flagged`, `log_entry`, `job_complete`

#### **Individual Model Endpoints**

- `POST /api/text/analyze` - Text analysis
- `POST /api/image/classify` - Image classification
- `POST /api/audio/analyze` - Audio transcription
- `POST /api/video/deepfake-detect` - Deepfake detection
- `POST /api/file/malware-scan` - Malware scanning
- `GET /api/browse/list` - File browser

---

## 🧠 Architecture Deep Dive

### Model Registry Pattern

The system uses a **central model registry** (`ModelRegistry`) to manage GPU-accelerated models efficiently:

```python
# All models loaded at startup via FastAPI lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load all models to GPU
    await ModelRegistry.load_all()
    yield
    # Unload on shutdown
    await ModelRegistry.unload_all()

# Access models anywhere in codebase
clip_model = ModelRegistry.get("clip")
bert_ner = ModelRegistry.get("bert_ner")
```

**Benefits**:
- Single GPU allocation prevents VRAM fragmentation
- Models shared across requests (no reload overhead)
- Lazy loading for heavy models (YOLOv8, malware classifiers)
- Thread-safe model access with locking

### Pipeline Architecture

Each analysis pipeline is an implementation of `AnalyzerInterface`:

```python
class AnalyzerInterface(ABC):
    @abstractmethod
    def validate(self) -> bool:
        """Validate analyzer configuration."""
        pass

    @abstractmethod
    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute analysis on input data."""
        pass
```

Pipelines are **composable** and **stateless**, enabling:
- Parallel execution across multiple files
- Easy addition of new analysis types
- Clear separation of concerns

### Tiered Risk Assessment

The system uses a **three-tier risk model**:

```python
HIGH_RISK (≥ 0.70):     # Requires immediate attention
    - Violence threshold raised to 0.70 (from 0.50)
    - Malware detection with ML confidence
    - YARA rule matches (signature-based)
    - Criminal keywords in context

MEDIUM_RISK (0.40-0.69): # Review recommended
    - Lower violence scores (0.40-0.69)
    - Suspicious file patterns (double extensions)
    - Contextual keyword matches
    - Face-only detections (no violence)

LOW_RISK (< 0.40):       # Likely benign
    - Clean files with no threats
    - Generic object detections (YOLO COCO classes)
    - Informational text content
```

**Design Rationale**: The 0.70 threshold for violence reduces false positives while maintaining high recall for genuine threats. Manual review feedback tunes these thresholds over time.

### Query Intelligence Pipeline

When a user provides a query (e.g., "weapons"), the system:

1. **Query Rewriter** (LLM-based):
   ```
   Input: "weapons"

   Output:
   - Variants: ["firearms", "guns", "knife", "blade", "armed person",
                "weapon in hand", "dangerous object", "combat scene"]
   - Crime Category: "violent_crime"
   - Intent: "investigate_threat"
   - Analysis Plan: ["1. Search for weapon keywords...", "2. Analyze images...", ...]
   ```

2. **Intelligence Engine**:
   - Loads policy for crime category (e.g., violence detection threshold = 0.70)
   - Expands with criminal synonyms and investigative terms

3. **Embedding Comparison**:
   - Each query variant encoded to 384-dim vector (text) or 512-dim (image)
   - Cosine similarity computed against all evidence embeddings
   - **Max-similarity scoring**: File ranked by best-matching variant
   - Returns top-k results across all variants

### Explainability & Transparency

Every risk score is decomposed into interpretable factors:

```json
{
  "file_hash": "abc123...",
  "overall_risk": 0.85,
  "factors": [
    {
      "factor": "Violence detected in image",
      "contribution": 0.70,
      "weight": 0.5,
      "source": "vision_pipeline"
    },
    {
      "factor": "Criminal keyword 'threat' found",
      "contribution": 0.15,
      "weight": 0.3,
      "source": "text_pipeline"
    },
    {
      "factor": "Hidden file attribute detected",
      "contribution": 0.05,
      "weight": 0.2,
      "source": "file_pipeline"
    }
  ],
  "explanation": "High risk due to violent imagery (0.92 confidence) and threatening language in associated text."
}
```

---

## 🎨 Design Decisions & Best Practices

### 1. **GPU Memory Management**

**Decision**: Single model registry with centralized CUDA allocation

**Rationale**:
- Prevents VRAM fragmentation from multiple model loads
- Enables model sharing across concurrent requests
- Reduces cold-start latency after first load

**Implementation**:
```python
# Force CUDA init before loading models
import torch
torch.cuda.init()

# Load all models to same device
device = torch.device("cuda:0")
models = {
    "clip": CLIPModel.from_pretrained(...).to(device),
    "bert_ner": AutoModel.from_pretrained(...).to(device)
}
```

### 2. **Raised Violence Threshold (0.70)**

**Decision**: Set violence detection threshold to 0.70 (previously 0.50)

**Rationale**:
- Reduces false positives from action movies, sports, gaming content
- Focuses investigator attention on truly concerning imagery
- Still maintains high recall (misses <5% of genuine threats in testing)

**Measured via**: Manual review feedback loop in production

### 3. **Three-Table to Two-Table Database Refactor**

**Decision**: Removed `threats` and `flagged_content` tables; consolidated into single `files` table with risk scores

**Rationale**:
- Eliminates redundancy (same file data in multiple tables)
- Simplifies queries and reporting logic
- Risk is a continuous spectrum, not binary classification
- Frontend can filter by risk threshold as needed

### 4. **Background Task Processing**

**Decision**: Use FastAPI `BackgroundTasks` + threading for analysis jobs

**Rationale**:
- Decouples API response time from analysis duration
- Enables long-running forensic scans (hours) without HTTP timeouts
- WebSocket provides real-time progress updates
- Job state persisted to disk for crash recovery

### 5. **FAISS CPU vs GPU**

**Decision**: Use `faiss-cpu` instead of `faiss-gpu`

**Rationale**:
- CPU FAISS sufficient for datasets <10M vectors
- Avoids CUDA version conflicts with PyTorch
- Simplifies deployment (no additional CUDA libs)
- Query latency <100ms for typical datasets

**Trade-off**: For very large indices (>10M vectors), consider migrating to `faiss-gpu`

### 6. **LLM-Based Query Rewriting**

**Decision**: Use Google Gemini (free tier) for query expansion instead of rule-based synonyms

**Rationale**:
- Generates contextually relevant investigative variants
- Adapts to different crime types (cybercrime vs violent crime)
- Creates analysis plans that guide pipeline execution
- Fallback to LLaMA for offline/local deployments

### 7. **Modular Pipeline Design**

**Decision**: Each analyzer is an independent module with `validate()` and `analyze()` methods

**Benefits**:
- Easy to add new analysis types (DNA, network traffic, browser history)
- Pipelines can be selectively enabled/disabled
- Clean separation of concerns (vision doesn't know about malware)
- Testable in isolation

### 8. **WebSocket Event Broadcasting**

**Decision**: Use per-job asyncio queues for WebSocket event distribution

**Rationale**:
- Multiple clients can monitor same job
- Backpressure handling (drop events if client too slow)
- Clean separation: background thread → queue → async WebSocket handler

### 9. **Incremental Vector Indexing**

**Decision**: Build FAISS index during analysis, not post-processing

**Rationale**:
- Enables search before analysis completes
- Avoids large post-processing phase
- Index persists to disk for future queries

### 10. **No Authentication Layer (Yet)**

**Decision**: No built-in auth in v2.0

**Rationale**:
- Designed for single-investigator workstations or trusted networks
- Deploy behind VPN or reverse proxy (nginx + OAuth2)
- Future: Add JWT-based auth for multi-user deployments

---

## 📈 System Flow Diagrams

### Complete Analysis Lifecycle

```
┌────────────────────────────────────────────────────────────────┐
│  USER ACTION: Click "Start Analysis"                          │
└───────────────────────────┬────────────────────────────────────┘
                            │
                            ▼
                ┌───────────────────────┐
                │  Frontend (React)     │
                │  • Validate inputs    │
                │  • POST /analyze      │
                └───────┬───────────────┘
                        │
                        ▼
        ┌───────────────────────────────┐
        │  Backend: forensics.router    │
        │  analyze_evidence()           │
        └───────┬───────────────────────┘
                │
                ├─→ Generate job_id (UUID)
                ├─→ Create job_cache entry
                ├─→ Persist to history JSON
                ├─→ Return job_id to frontend
                │
                ▼
        ┌───────────────────────────────────────┐
        │  Background Thread:                   │
        │  _run_forensic_job(job_id, ...)       │
        └───────┬───────────────────────────────┘
                │
                ├─→ Step 1: Query Intelligence
                │   ├─ QueryRewriter.rewrite()
                │   ├─ IntelligenceEngine.expand_query()
                │   └─ Load crime policy & thresholds
                │
                ├─→ Step 2: File Discovery
                │   ├─ os.walk(evidence_path)
                │   └─ AssetAnalyzer.analyze_asset() per file
                │       ├─ SHA-256 hash
                │       ├─ MIME type detection
                │       ├─ Classify asset type
                │       └─ Initial risk level
                │
                ├─→ Step 3: Pipeline Routing
                │   │
                │   ├─ FOR EACH selected_model:
                │   │   │
                │   │   ├─ IF model == "vision" AND is_image:
                │   │   │   ├─ Load YOLO model (lazy)
                │   │   │   ├─ Detect objects
                │   │   │   ├─ Load CLIP model
                │   │   │   ├─ Generate embedding
                │   │   │   ├─ Compare with query variants
                │   │   │   ├─ Run violence detection
                │   │   │   ├─ Run face detection
                │   │   │   ├─ Run OCR
                │   │   │   └─ Emit: image_flagged, model_result
                │   │   │
                │   │   ├─ IF model == "text" AND is_text:
                │   │   │   ├─ Extract text (PyPDF2 / raw read)
                │   │   │   ├─ BERT NER extraction
                │   │   │   ├─ Criminal keyword matching
                │   │   │   ├─ Sentence embedding (MiniLM)
                │   │   │   ├─ Query similarity scoring
                │   │   │   ├─ Store in FAISS vector index
                │   │   │   └─ Emit: model_result
                │   │   │
                │   │   ├─ IF model == "malware" AND is_executable:
                │   │   │   ├─ PE header parsing (pefile)
                │   │   │   ├─ YARA rule scanning
                │   │   │   ├─ Feature extraction
                │   │   │   ├─ ML classifier prediction
                │   │   │   ├─ Docker sandbox (if enabled)
                │   │   │   └─ Emit: model_result
                │   │   │
                │   │   └─ ... (similar for audio, file, deepfake)
                │   │
                │   ├─ After each file processed:
                │   │   ├─ Update job progress
                │   │   ├─ Broadcast file_processed event
                │   │   └─ Update ETA estimate
                │   │
                │   └─ After each model completes:
                │       └─ Store result in job["results"][model]
                │
                ├─→ Step 4: Advanced Intelligence
                │   ├─ Explainability: compute risk factors
                │   ├─ Cross-Modal Correlation: cluster evidence
                │   └─ Vector Store: persist FAISS index
                │
                ├─→ Step 5: Report Generation
                │   ├─ Aggregate all findings
                │   ├─ Generate AI summary (Gemini)
                │   ├─ Create PDF report (ReportLab)
                │   └─ Save to OUTPUT/intelligence/{job_id}.json
                │
                └─→ Step 6: Completion
                    ├─ Set job status = "completed"
                    ├─ Broadcast job_complete event
                    └─ Emit final intelligence report
                            │
                            ▼
        ┌───────────────────────────────────────┐
        │  Frontend Receives Results            │
        ├───────────────────────────────────────┤
        │  • Parse intelligence JSON            │
        │  • Populate Threat Ledger             │
        │  • Display Flagged Images             │
        │  • Show AI Summary                    │
        │  • Enable Vector Search               │
        │  • Render Risk Explanations           │
        │  • Visualize Evidence Clusters        │
        └───────────────────────────────────────┘
```

### Cross-Modal Correlation Algorithm

The **CrossModalCorrelator** links related evidence using three signals:

1. **Keyword Overlap**:
   ```python
   similarity = len(keywords_A & keywords_B) / min(len(keywords_A), len(keywords_B))
   if similarity > 0.3:  # 30% overlap
       create_correlation()
   ```

2. **Spatial Proximity**:
   ```python
   if same_directory(file_A, file_B):
       boost_correlation(weight=0.3)
   ```

3. **Temporal Patterns**:
   ```python
   if abs(timestamp_A - timestamp_B) < 3600:  # 1 hour window
       boost_correlation(weight=0.2)
   ```

**Output**: Evidence clusters like:
```json
{
  "cluster_id": "cluster_001",
  "files": ["img_01.jpg", "threat_note.txt", "suspicious.exe"],
  "correlation_reason": "All contain keyword 'target', located in same folder",
  "cluster_risk_score": 0.88
}
```

---

## 💡 Design Patterns & Principles

### SOLID Principles Applied

1. **Single Responsibility**: Each pipeline handles one modality (vision, text, malware)
2. **Open/Closed**: Easy to add new analyzers without modifying existing code
3. **Liskov Substitution**: All analyzers implement `AnalyzerInterface`
4. **Interface Segregation**: Pipelines don't depend on unnecessary methods
5. **Dependency Inversion**: High-level orchestrator depends on `AnalyzerInterface`, not concrete classes

### Concurrency Model

- **API Layer**: Async (asyncio) for handling concurrent HTTP requests
- **Analysis Jobs**: Threading (background threads) for CPU/GPU-bound ML tasks
- **WebSocket**: Async (asyncio) for event broadcasting
- **Synchronization**: Thread-safe queues (`asyncio.Queue`) bridge threads and async coroutines

**Rationale**: ML inference is CPU/GPU-bound, not I/O-bound, so threading is optimal. Async handles I/O (network, disk) efficiently.

### Error Handling Strategy

```python
# Graceful degradation: if one model fails, others continue
try:
    result = vision_pipeline.analyze(image)
except Exception as e:
    logger.error(f"Vision pipeline failed: {e}")
    result = {"status": "error", "message": str(e)}
    # Job continues with other models

# Skipped files: track but don't fail
if file_too_large or file_corrupted:
    emit_log(job, "warn", f"Skipped {filename}: {reason}")
    continue  # process next file
```

### Configuration Management

All settings centralized in `Backend/src/config.py`:
- Paths: models, evidence, output
- GPU: device ID, VRAM limits
- Thresholds: violence, keyword, similarity
- API keys: Google, VirusTotal, OpenAI

**Environment override**: All settings can be overridden via `.env` file

---

## 🎯 Use Cases

1. **Law Enforcement**: Digital evidence triage in cybercrime investigations
2. **Cybersecurity**: Malware analysis and threat intelligence
3. **Corporate Security**: Insider threat detection and forensic auditing
4. **Academic Research**: AI/ML for cybersecurity and digital forensics
5. **CTF Competitions**: Automated evidence discovery and analysis
6. **Incident Response**: Rapid threat assessment during security breaches

---

## 🤝 Contributing

### Adding a New Analysis Pipeline

1. Create a new file in `Backend/src/analyzers/`:
   ```python
   from .interface import AnalyzerInterface

   class MyCustomPipeline(AnalyzerInterface):
       def validate(self) -> bool:
           # Check dependencies
           return True

       def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
           # Implement analysis logic
           return {"status": "success", "findings": [...]}
   ```

2. Register in `orchestrator.py`:
   ```python
   self.pipelines["custom"] = MyCustomPipeline()
   ```

3. Add to frontend model selection in `ModelSelection.tsx`

### Adding a New Model to Registry

1. Add loader in `api/services/model_registry.py`:
   ```python
   @staticmethod
   async def _load_my_model():
       from transformers import MyModel
       model = MyModel.from_pretrained("org/model-name")
       return model.to(ModelRegistry._device)
   ```

2. Register in `LOADERS` dict:
   ```python
   LOADERS = {
       "my_model": _load_my_model,
       ...
   }
   ```

3. Call `ModelRegistry.get("my_model")` in your pipeline

---

## 🔒 Security Considerations

1. **Sandboxing**: Malware analysis optionally runs in Docker containers (set `DOCKER_ENABLED=true`)
2. **Path Traversal**: All file paths validated and sanitized
3. **Code Injection**: No `eval()` or `exec()` used; all user input validated with Pydantic
4. **CORS**: Configure `allow_origins` in production (currently allows all for dev)
5. **API Keys**: Store in `.env` file, never commit to git
6. **Evidence Integrity**: All files hashed (SHA-256) for chain-of-custody

---

## 📝 Configuration Reference

### Environment Variables (.env)

```bash
# Google Gemini API (for summarization agent)
GOOGLE_API_KEY=your_gemini_api_key_here

# VirusTotal API (optional, for malware scanning)
VIRUSTOTAL_API_KEY=your_virustotal_key

# OpenAI API (optional, for master agent)
OPENAI_API_KEY=your_openai_key

# Remote GPU inference (optional, for Kaggle/Colab offload)
USE_REMOTE_INFERENCE=false
KAGGLE_INFERENCE_URL=https://xxxx.ngrok-free.app

# Docker malware sandbox
DOCKER_ENABLED=false
DOCKER_MALWARE_IMAGE=malware-detector:latest
DOCKER_TIMEOUT=300

# Model settings
HF_MODEL_NAME=distilbert-base-uncased
VECTOR_TEXT_MODEL=all-MiniLM-L6-v2

# Directories (optional overrides)
# YARA_RULES_DIR=/path/to/yara/rules
# YARA_RULES_FILE=/path/to/rules.yar
```

### Key Configuration Parameters (config.py)

```python
# Violence detection
VIOLENCE_THRESHOLD = 0.70          # High threshold reduces false positives

# Query engine
QUERY_MAX_VARIANTS = 8             # LLM generates 8 query variants
QUERY_LLM_TEMPERATURE = 0.7        # Creativity vs consistency

# Batch processing
BATCH_SIZE_IMAGES = 8              # GPU batch size
BATCH_SIZE_TEXT = 16               # Text embedding batch size

# Vector search
VECTOR_TEXT_DIM = 384              # all-MiniLM-L6-v2 output
VECTOR_IMAGE_DIM = 512             # CLIP ViT-B/32 output

# Fusion & correlation
FUSION_KEYWORD_THRESHOLD = 0.3     # 30% keyword overlap
FUSION_SPATIAL_WEIGHT = 0.3        # Same directory = 30% boost

# GPU
GPU_ID = 0                         # CUDA device ID
VRAM_LIMIT = 0.9                   # 90% VRAM utilization
```

---

## 🧪 Testing

### Run Backend Tests

```bash
cd Backend
pytest tests/ -v --cov=src
```

### Run Frontend Tests

```bash
cd Frontend
npm run test
```

### End-to-End Test

```bash
# Start services
docker-compose up -d

# Run test analysis
curl -X POST "http://localhost:8000/api/master-agent/analyze" \
  -H "Content-Type: application/json" \
  -d '{"evidencePath": "Backend/EVIDENCE_LOCKER/test_samples", "selectedModels": ["vision", "text"]}'

# Monitor WebSocket events
# (Use browser dev tools or wscat)
```

---

## 📊 Performance Benchmarks

| Scenario | Hardware | Files | Time | Throughput |
|----------|----------|-------|------|------------|
| Quick Scan (text+file) | CPU (i7-12700K) | 10,000 | 8 min | ~20 files/sec |
| Standard Scan (vision+text) | RTX 3090 | 10,000 | 25 min | ~6.7 files/sec |
| Deep Scan (all models) | RTX 3090 | 10,000 | 45 min | ~3.7 files/sec |
| Malware Focus | CPU (i7-12700K) | 5,000 EXE | 12 min | ~7 files/sec |
| Large Dataset (batch) | 4x A100 GPU | 1,000,000 | 8 hours | ~35 files/sec |

*Benchmarks are approximate and vary based on file sizes, complexity, and hardware.*

---

## 🐛 Troubleshooting

### GPU Not Detected

```bash
# Check CUDA availability
python -c "import torch; print(torch.cuda.is_available())"

# Check nvidia-smi
nvidia-smi

# Verify PyTorch CUDA version
python -c "import torch; print(torch.version.cuda)"
```

**Fix**: Install CUDA-enabled PyTorch:
```bash
pip install torch torchvision --index-url https://download.pytorch.org/whl/cu117
```

### Out of Memory (OOM)

**Symptoms**: `RuntimeError: CUDA out of memory`

**Solutions**:
1. Reduce batch sizes in `config.py`:
   ```python
   BATCH_SIZE_IMAGES = 4  # Reduce from 8
   ```
2. Use smaller models:
   - YOLOv8n instead of YOLOv8x
   - Whisper tiny instead of base
3. Enable remote inference (offload to Kaggle GPU):
   ```bash
   USE_REMOTE_INFERENCE=true
   KAGGLE_INFERENCE_URL=https://your-ngrok-url.app
   ```

### FAISS Not Found

**Error**: `ModuleNotFoundError: No module named 'faiss'`

**Fix**:
```bash
pip install faiss-cpu
```

### YARA Rules Not Loading

**Error**: `YARA rules not found`

**Fix**:
```bash
mkdir -p Backend/MODELS/yara_rules
# Add .yar files to this directory
# Or set YARA_RULES_FILE=/path/to/rules.yar in .env
```

---

## 📚 Additional Resources

- **FastAPI Documentation**: https://fastapi.tiangolo.com/
- **YOLOv8 Docs**: https://docs.ultralytics.com/
- **CLIP Paper**: https://arxiv.org/abs/2103.00020
- **FAISS Documentation**: https://faiss.ai/
- **HuggingFace Transformers**: https://huggingface.co/docs/transformers
- **Whisper STT**: https://github.com/openai/whisper

---

## ⚠️ Disclaimer

This software is intended **exclusively for lawful purposes**:
- Academic research in AI/ML for cybersecurity
- Authorized digital forensics investigations
- Law enforcement evidence processing
- Corporate security auditing with proper authorization
- Penetration testing and red team exercises (with consent)
- CTF competitions and security education

**Prohibited Uses**:
- Unauthorized surveillance or monitoring
- Processing data without legal authority
- Violating privacy laws or regulations
- Any malicious or illegal activities

**The authors and contributors are not responsible for misuse of this software.**

---

## 📄 License

This project is provided for research and educational purposes. See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- OpenAI for CLIP and Whisper models
- HuggingFace for Transformers library
- Ultralytics for YOLOv8
- Google for Gemini API
- MediaPipe for face detection
- FAISS team for vector search

---

## 📧 Contact & Support

- **Issues**: [GitHub Issues](https://github.com/adityapandey13-yours/Digital_Forensics/issues)
- **Discussions**: [GitHub Discussions](https://github.com/adityapandey13-yours/Digital_Forensics/discussions)

---

**Built with ❤️ for the digital forensics and cybersecurity community.**

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

**Note on Third-Party Models and Dependencies**: 
While the core engine is open-source under Apache 2.0, this project utilizes pre-trained models (e.g., YOLOv8, CLIP, Whisper) and datasets that are subject to their own respective licenses. Users are responsible for reviewing and adhering to the licenses of individual third-party weights and dependencies, especially regarding commercial use.
