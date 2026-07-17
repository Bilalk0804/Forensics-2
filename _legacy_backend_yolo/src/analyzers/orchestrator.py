"""
Forensic Analysis Orchestrator Module
Coordinates the entire forensic analysis workflow.
Manages model execution, result aggregation, and reporting.
"""

import logging
import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import sqlite3
from pathlib import Path
from dataclasses import asdict

from .model_manager import ModelManager
from .asset_analyzer import AssetAnalyzer, AssetMetadata, AssetType, RiskLevel
from .interface import AnalyzerInterface

logger = logging.getLogger("SENTINEL_ORCHESTRATOR")


class AnalysisResult:
    """Container for analysis results."""
    
    def __init__(self, asset_metadata: AssetMetadata):
        self.asset_metadata = asset_metadata
        self.timestamp = datetime.now().isoformat()
        self.model_results = {}
        self.pipeline_results = {}
        self.aggregated_findings = []
        self.overall_risk_score = 0
        self.recommendations = []
        self.execution_time = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "timestamp": self.timestamp,
            "asset": asdict(self.asset_metadata),
            "model_results": self.model_results,
            "pipeline_results": self.pipeline_results,
            "findings": self.aggregated_findings,
            "overall_risk_score": self.overall_risk_score,
            "recommendations": self.recommendations,
            "execution_time_seconds": self.execution_time
        }


class ForensicOrchestrator:
    """Orchestrates forensic analysis utilizing all models and pipelines."""

    def __init__(
        self,
        db_handler: Optional[Any] = None,
        gpu_id: int = 0,
        vram_limit: float = 0.9,
        enable_cache: bool = True
    ):
        """
        Initialize Forensic Orchestrator.
        
        Args:
            db_handler: Database handler for result storage
            gpu_id: GPU device ID
            vram_limit: VRAM utilization limit
            enable_cache: Enable result caching
        """
        self.db_handler = db_handler
        self.model_manager = ModelManager(gpu_id, vram_limit)
        self.asset_analyzer = AssetAnalyzer()
        self.enable_cache = enable_cache
        self.result_cache = {}
        self.analysis_history = []
        logger.info("ForensicOrchestrator initialized")

    def orchestrate_analysis(
        self,
        file_path: str,
        force_reanalyze: bool = False,
        include_pipelines: Optional[List[str]] = None
    ) -> AnalysisResult:
        """
        Master analysis orchestration function.
        Coordinates all analysis workflows for a single asset.
        
        Args:
            file_path: Path to file to analyze
            force_reanalyze: Force re-analysis even if cached
            include_pipelines: Specific pipelines to run (None = all recommended)
            
        Returns:
            AnalysisResult with all findings
        """
        import time
        start_time = time.time()

        try:
            # Step 1: Asset Analysis
            logger.info(f"Starting orchestration for: {file_path}")
            asset_metadata = self.asset_analyzer.analyze_asset(file_path)
            
            # Check cache
            if self.enable_cache and not force_reanalyze:
                cached = self._check_cache(asset_metadata.file_hash)
                if cached:
                    logger.info(f"Returning cached result for {Path(file_path).name}")
                    return cached

            # Step 2: Create result container
            result = AnalysisResult(asset_metadata)

            # Step 3: Select and run models
            logger.info(f"Asset Type: {asset_metadata.asset_type.value} | "
                       f"Risk Level: {asset_metadata.risk_level.value}")
            
            self._execute_models(
                asset_metadata,
                result
            )

            # Step 4: Run pipelines
            pipelines = include_pipelines or asset_metadata.recommended_pipelines
            self._execute_pipelines(
                asset_metadata,
                result,
                pipelines
            )

            # Step 5: Aggregate findings
            self._aggregate_findings(result)

            # Step 6: Generate recommendations
            self._generate_recommendations(result)

            # Step 7: Store results
            if self.db_handler:
                self._store_results(result)

            # Cache results
            if self.enable_cache:
                self._cache_result(asset_metadata.file_hash, result)

            result.execution_time = time.time() - start_time
            self.analysis_history.append(result)

            logger.info(f"Analysis complete in {result.execution_time:.2f}s")
            return result

        except Exception as e:
            logger.error(f"Orchestration failed for {file_path}: {e}", exc_info=True)
            raise

    def _execute_models(
        self,
        asset_metadata: AssetMetadata,
        result: AnalysisResult
    ):
        """Execute recommended models."""
        logger.info(f"Executing {len(asset_metadata.recommended_models)} models")
        
        for model_name in asset_metadata.recommended_models:
            try:
                logger.info(f"Loading model: {model_name}")
                model = self.model_manager.load_model(model_name)
                
                if model is None:
                    logger.warning(f"Failed to load {model_name}")
                    continue

                # Execute model based on type
                model_result = self._run_model(
                    model,
                    model_name,
                    asset_metadata
                )

                result.model_results[model_name] = model_result

            except Exception as e:
                logger.error(f"Model {model_name} execution failed: {e}")
                result.model_results[model_name] = {
                    "status": "error",
                    "error": str(e)
                }

    def _run_model(
        self,
        model: Any,
        model_name: str,
        asset_metadata: AssetMetadata
    ) -> Dict[str, Any]:
        """Execute a single model."""
        try:
            if "yolo" in model_name.lower():
                return self._run_yolo_model(model, asset_metadata)
            elif "lstm" in model_name.lower() or "deepfake" in model_name.lower():
                return self._run_deepfake_model(model, asset_metadata)
            elif "efficientnet" in model_name.lower():
                return self._run_classification_model(model, asset_metadata)
            elif "roberta" in model_name.lower() or "bert" in model_name.lower():
                return self._run_text_model(model, asset_metadata)
            elif "tabnet" in model_name.lower():
                return self._run_tabnet_model(model, asset_metadata)
            else:
                logger.warning(f"Unknown model type: {model_name}")
                return {"status": "unknown_model"}

        except Exception as e:
            logger.error(f"Error running {model_name}: {e}")
            return {"status": "error", "error": str(e)}

    def _run_yolo_model(
        self,
        model: Any,
        asset_metadata: AssetMetadata
    ) -> Dict[str, Any]:
        """Run YOLO object detection model."""
        try:
            from pathlib import Path
            
            if asset_metadata.asset_type not in [AssetType.IMAGE, AssetType.VIDEO]:
                return {"status": "skipped", "reason": "Not image/video"}

            results = model.predict(asset_metadata.file_path, conf=0.5)
            
            detections = []
            for r in results:
                if hasattr(r, 'boxes'):
                    for box in r.boxes:
                        detections.append({
                            "class": int(box.cls),
                            "confidence": float(box.conf),
                            "coordinates": box.xyxy.tolist()
                        })

            return {
                "status": "success",
                "model": "YOLOv8",
                "detections_count": len(detections),
                "detections": detections[:10]  # Limit to top 10
            }

        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _run_deepfake_model(
        self,
        model: Any,
        asset_metadata: AssetMetadata
    ) -> Dict[str, Any]:
        """Run deepfake detection model."""
        try:
            if asset_metadata.asset_type not in [AssetType.IMAGE, AssetType.VIDEO]:
                return {"status": "skipped", "reason": "Not image/video"}

            # Load image for analysis
            from PIL import Image
            import numpy as np
            
            img = Image.open(asset_metadata.file_path)
            img_array = np.array(img)
            
            # Make prediction
            predictions = model.predict(np.expand_dims(img_array, axis=0))
            
            confidence = float(predictions[0][0])
            is_deepfake = confidence > 0.5

            return {
                "status": "success",
                "model": "LSTM Deepfake Detector",
                "is_deepfake": is_deepfake,
                "confidence": confidence,
                "recommendation": "SUSPICIOUS" if is_deepfake else "AUTHENTIC"
            }

        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _run_classification_model(
        self,
        model: Any,
        asset_metadata: AssetMetadata
    ) -> Dict[str, Any]:
        """Run image classification model."""
        try:
            import torch
            from torchvision import transforms
            from PIL import Image

            if asset_metadata.asset_type != AssetType.IMAGE:
                return {"status": "skipped", "reason": "Not an image"}

            # Prepare image
            img = Image.open(asset_metadata.file_path).convert('RGB')
            preprocess = transforms.Compose([
                transforms.Resize(256),
                transforms.CenterCrop(224),
                transforms.ToTensor(),
                transforms.Normalize(
                    mean=[0.485, 0.456, 0.406],
                    std=[0.229, 0.224, 0.225]
                )
            ])

            img_tensor = preprocess(img).unsqueeze(0)

            with torch.no_grad():
                outputs = model(img_tensor)
                probabilities = torch.softmax(outputs, dim=1)

            return {
                "status": "success",
                "model": "EfficientNet",
                "top_confidence": float(probabilities.max().item()),
                "classification": "Image analyzed successfully"
            }

        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _run_text_model(
        self,
        model: Any,
        asset_metadata: AssetMetadata
    ) -> Dict[str, Any]:
        """Run text analysis model."""
        try:
            import torch
            from transformers import AutoTokenizer
            
            if asset_metadata.asset_type not in [AssetType.TEXT, AssetType.DOCUMENT]:
                return {"status": "skipped", "reason": "Not text document"}

            # Read text
            with open(asset_metadata.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()[:512]  # Limit to 512 chars

            tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
            inputs = tokenizer(text, return_tensors="pt", truncation=True)

            with torch.no_grad():
                outputs = model(**inputs)

            # Extract meaningful outputs instead of generic message
            logits = outputs.logits if hasattr(outputs, 'logits') else None
            result = {
                "status": "success",
                "model": "Text Analysis (BERT-based)",
                "text_length": len(text),
            }
            if logits is not None:
                probs = torch.softmax(logits, dim=-1)
                result["top_confidence"] = float(probs.max().item())
                result["predicted_class"] = int(probs.argmax(dim=-1).item())
            else:
                result["analysis"] = "Text embeddings computed"

            return result

        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _run_tabnet_model(
        self,
        model: Any,
        asset_metadata: AssetMetadata
    ) -> Dict[str, Any]:
        """Run TabNet metadata analysis model."""
        try:
            # Prepare metadata features
            import numpy as np
            
            features = self._extract_metadata_features(asset_metadata)
            
            if features is None:
                return {"status": "skipped", "reason": "Could not extract features"}

            prediction = model.predict(np.array([features]))
            
            return {
                "status": "success",
                "model": "TabNet Metadata Analyzer",
                "anomaly_score": float(prediction[0]),
                "is_anomalous": prediction[0] > 0.5
            }

        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _extract_metadata_features(self, asset_metadata: AssetMetadata) -> Optional[List]:
        """Extract features from asset metadata for TabNet."""
        try:
            return [
                asset_metadata.file_size,
                len(asset_metadata.file_hash),
                len(asset_metadata.file_extension),
                1 if asset_metadata.is_suspicious else 0,
                len(asset_metadata.analysis_flags)
            ]
        except Exception as e:
            logger.warning(f"Feature extraction failed: {e}")
            return None

    def _get_pipeline_instance(self, pipeline_name: str):
        """Instantiate a pipeline by name."""
        try:
            if "text" in pipeline_name:
                from .text_pipeline import TextPipeline
                return TextPipeline(db=self.db_handler)
            elif "vision" in pipeline_name:
                from .vision_pipeline import VisionPipeline
                return VisionPipeline(db=self.db_handler)
            elif "malware" in pipeline_name:
                from .malware_pipeline import MalwarePipeline
                return MalwarePipeline(db=self.db_handler)
            else:
                logger.warning(f"No pipeline class mapped for: {pipeline_name}")
                return None
        except Exception as e:
            logger.error(f"Failed to instantiate pipeline {pipeline_name}: {e}")
            return None

    def _execute_pipelines(
        self,
        asset_metadata: AssetMetadata,
        result: AnalysisResult,
        pipelines: List[str]
    ):
        """Execute recommended pipelines with real analysis."""
        logger.info(f"Executing {len(pipelines)} pipelines")
        
        for pipeline_name in pipelines:
            try:
                logger.info(f"Running pipeline: {pipeline_name}")
                
                pipeline = self._get_pipeline_instance(pipeline_name)
                if pipeline is None:
                    result.pipeline_results[pipeline_name] = {
                        "status": "skipped",
                        "reason": f"No implementation for pipeline: {pipeline_name}"
                    }
                    continue

                # Validate the pipeline before running
                try:
                    pipeline.validate()
                except Exception as ve:
                    logger.warning(f"Pipeline {pipeline_name} validation failed: {ve}")
                    result.pipeline_results[pipeline_name] = {
                        "status": "validation-failed",
                        "error": str(ve)
                    }
                    continue

                # Run pipeline analysis on the file
                pipeline_result = pipeline.analyze(asset_metadata.file_path)

                result.pipeline_results[pipeline_name] = {
                    "status": "completed",
                    "pipeline": pipeline_name,
                    "results": pipeline_result
                }

            except Exception as e:
                logger.error(f"Pipeline {pipeline_name} failed: {e}", exc_info=True)
                result.pipeline_results[pipeline_name] = {
                    "status": "error",
                    "error": str(e)
                }

    def _aggregate_findings(self, result: AnalysisResult):
        """Aggregate findings from all models and pipelines."""
        findings = []
        risk_scores = []

        # Extract findings from model results
        for model_name, model_result in result.model_results.items():
            if model_result.get("status") == "success":
                if "detections_count" in model_result:
                    findings.append({
                        "source": model_name,
                        "type": "detections",
                        "count": model_result["detections_count"]
                    })
                
                if "is_deepfake" in model_result:
                    findings.append({
                        "source": model_name,
                        "type": "authenticity",
                        "value": "DEEPFAKE DETECTED" if model_result["is_deepfake"] else "AUTHENTIC"
                    })
                
                if "is_anomalous" in model_result:
                    findings.append({
                        "source": model_name,
                        "type": "anomaly",
                        "value": "ANOMALY DETECTED" if model_result["is_anomalous"] else "NORMAL"
                    })

                if "top_confidence" in model_result:
                    findings.append({
                        "source": model_name,
                        "type": "classification",
                        "confidence": model_result["top_confidence"]
                    })

        # Extract findings from pipeline results
        for pipeline_name, pipeline_result in result.pipeline_results.items():
            if pipeline_result.get("status") == "completed":
                pr = pipeline_result.get("results", {})
                if isinstance(pr, dict):
                    if pr.get("sensitive_data_found"):
                        findings.append({
                            "source": pipeline_name,
                            "type": "sensitive_data",
                            "risk_level": pr.get("risk_level", "HIGH"),
                            "details": {
                                "credit_cards": pr.get("credit_cards", 0),
                                "ssn_found": pr.get("ssn_found", 0),
                                "keywords": pr.get("suspicious_keywords", []),
                            }
                        })
                    elif pr.get("suspicious_keywords"):
                        findings.append({
                            "source": pipeline_name,
                            "type": "suspicious_content",
                            "risk_level": pr.get("risk_level", "MEDIUM"),
                            "keywords": pr.get("suspicious_keywords", [])
                        })
                    if pr.get("violence_detected"):
                        findings.append({
                            "source": pipeline_name,
                            "type": "violence",
                            "score": pr.get("violence_score", 0)
                        })
                    if pr.get("detection_count", 0) > 0:
                        findings.append({
                            "source": pipeline_name,
                            "type": "detections",
                            "count": pr.get("detection_count", 0)
                        })

        result.aggregated_findings = findings
        
        # Calculate overall risk score
        base_risk = {
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4
        }
        
        result.overall_risk_score = base_risk.get(result.asset_metadata.risk_level, 1)
        result.overall_risk_score += len(findings)

    def _generate_recommendations(self, result: AnalysisResult):
        """Generate recommendations based on findings."""
        recommendations = []

        if result.asset_metadata.is_suspicious:
            recommendations.append("Asset flagged as suspicious - escalate to analyst")

        if any("deepfake" in f.get("type", "") for f in result.aggregated_findings):
            recommendations.append("Deepfake indicators detected - verify authenticity")

        if any("anomaly" in f.get("type", "") for f in result.aggregated_findings):
            recommendations.append("Metadata anomalies detected - investigate origin")

        if result.asset_metadata.analysis_flags:
            recommendations.append(f"Security flags: {', '.join(result.asset_metadata.analysis_flags)}")

        if result.overall_risk_score >= 5:
            recommendations.append("HIGH PRIORITY: Escalate to senior analyst")

        result.recommendations = recommendations

    def _store_results(self, result: AnalysisResult):
        """Store analysis results to database."""
        try:
            if not self.db_handler:
                logger.warning("No DB handler — results not persisted")
                return

            # Insert the file record if it doesn't exist
            file_hash = getattr(result.asset_metadata, 'file_hash', '')
            file_size = getattr(result.asset_metadata, 'file_size', 0)
            mime_type = getattr(result.asset_metadata, 'mime_type', 'application/octet-stream')

            if hasattr(self.db_handler, 'insert_file'):
                self.db_handler.insert_file(
                    result.asset_metadata.file_path,
                    file_hash,
                    file_size,
                    mime_type,
                )

            # Store aggregated findings as an artifact
            artifact_metadata = json.dumps({
                "asset_type": result.asset_metadata.asset_type.value,
                "model_results": result.model_results,
                "pipeline_results": result.pipeline_results,
                "findings": result.aggregated_findings,
                "recommendations": result.recommendations,
                "execution_time": result.execution_time,
                "timestamp": result.timestamp,
            }, default=str)

            if hasattr(self.db_handler, 'insert_artifact'):
                # We need the file_id — query it back
                conn = self.db_handler.get_connection()
                try:
                    cursor = conn.execute(
                        "SELECT file_id FROM files WHERE file_path = ?",
                        (result.asset_metadata.file_path,)
                    )
                    row = cursor.fetchone()
                    file_id = row[0] if row else None
                finally:
                    conn.close()

                if file_id is not None:
                    self.db_handler.insert_artifact(
                        file_id=file_id,
                        pipeline_name="orchestrator",
                        risk_level=result.asset_metadata.risk_level.value,
                        description=f"Orchestrated analysis: {len(result.aggregated_findings)} findings, risk={result.overall_risk_score}",
                        metadata=artifact_metadata,
                    )

            logger.info(f"Results stored for {result.asset_metadata.file_path}")

        except Exception as e:
            logger.warning(f"Could not store results: {e}", exc_info=True)

    def _check_cache(self, file_hash: str) -> Optional[AnalysisResult]:
        """Check if analysis result is cached."""
        return self.result_cache.get(file_hash)

    def _cache_result(self, file_hash: str, result: AnalysisResult):
        """Cache analysis result."""
        self.result_cache[file_hash] = result
        logger.info(f"Result cached for hash {file_hash[:8]}...")

    def batch_analyze(
        self,
        file_paths: List[str],
        parallel: bool = False
    ) -> List[AnalysisResult]:
        """
        Analyze multiple files.
        
        Args:
            file_paths: List of file paths
            parallel: Use parallel processing if True
            
        Returns:
            List of analysis results
        """
        results = []
        
        for file_path in file_paths:
            try:
                result = self.orchestrate_analysis(file_path)
                results.append(result)
            except Exception as e:
                logger.error(f"Batch analysis failed for {file_path}: {e}")

        return results

    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get summary of all analyses."""
        if not self.analysis_history:
            return {"status": "no_analyses"}

        total_files = len(self.analysis_history)
        suspicious_count = sum(
            1 for r in self.analysis_history if r.asset_metadata.is_suspicious
        )
        
        critical_count = sum(
            1 for r in self.analysis_history 
            if r.asset_metadata.risk_level == RiskLevel.CRITICAL
        )

        return {
            "total_analyses": total_files,
            "suspicious_files": suspicious_count,
            "critical_risk_files": critical_count,
            "average_execution_time": sum(
                r.execution_time for r in self.analysis_history
            ) / total_files if total_files > 0 else 0
        }
