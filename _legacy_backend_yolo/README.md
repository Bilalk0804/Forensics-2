# Sentinel Core - Forensics Analysis System

A comprehensive digital forensics analysis platform utilizing computer vision, NLP, and LLM technologies.

## 🚀 Quick Start - Single-Button USB Analysis

The system now features **one-click USB analysis** with clear verdicts:

```bash
# Validate system
python validate_system.py

# Analyze USB drive
python analyze_usb.py E:/
```

**Verdicts:**
- ✅ **CLEAN** - Safe to use
- ⚠️ **SUSPICIOUS** - Review recommended  
- 🚨 **MALICIOUS** - Quarantine immediately
- ❓ **NOT_SURE** - Manual inspection required

For detailed usage instructions, see [USAGE_GUIDE.md](USAGE_GUIDE.md)

## 📊 Analysis Pipelines

The system runs 5 specialized AI pipelines:

1. **File Integrity** - Hidden files, double extensions, MIME validation
2. **Malware Detection** - PE header analysis, URL classification
3. **Vision Analysis** - YOLO object detection, violence detection
4. **Text/NLP** - Keyword scanning, sensitive data detection
5. **AI Summarization** - Google Gemini Pro case summary

## Project Structure

```
Sentinel_Core/
├── 00_EVIDENCE_LOCKER/        # MOUNT POINTS ONLY. Read-Only.
├── 01_OUTPUT/                 # The "Blackboard" - system outputs
│   ├── sentinel_case.db       # SQLite Database (Single Source of Truth)
│   ├── logs/                  # System logs
│   └── reports/               # Generated PDF reports
├── 02_MODELS/                 # Local model files
│   ├── vision/                # YOLOv8x.pt, ResNet.pth
│   ├── nlp/                   # Spacy models
│   └── llm/                   # Quantized LLM models
├── 03_DEPENDENCIES/           # Offline package wheels
└── src/
    ├── main.py                # Entry point (The Commander)
    ├── config.py              # Configuration settings
    ├── db/                    # Database layer
    ├── core/                  # System logic
    ├── analyzers/             # Analysis pipelines (4 specialists)
    └── reporting/             # Report generation
```

## Getting Started

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Configure settings in `src/config.py`

3. Run the main application:
   ```bash
   python src/main.py
   ```

## Architecture

- **Database Layer**: SQLite database for persistent storage of artifacts and analysis results
- **Ingestion**: File walking with hashing and MIME-type detection
- **Analyzers**: Four specialized analysis pipelines:
  - Vision: YOLO object detection and classification
  - Text: OCR and LLM-based analysis
  - File: Header analysis and tampering detection
  - (Additional analyzers as needed)
- **Reporting**: PDF report generation from database results

## Configuration

Key settings are managed in `src/config.py`:
- GPU configuration (GPU ID, VRAM limits)
- Path constants for models and data directories
