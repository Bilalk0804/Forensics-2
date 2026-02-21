"""
Master Agent Pipeline Module
Orchestrates analysis using OpenAI SDK to coordinate multiple analysis models.
Integrates with local forensic analyzers and orchestrator.
"""

import os
import logging
import json
from typing import Any, Dict, List, Optional
from datetime import datetime

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

from .interface import AnalyzerInterface
from .orchestrator import ForensicOrchestrator, AnalysisResult
from .asset_analyzer import AssetAnalyzer, AssetType, RiskLevel
from .model_manager import ModelManager

logger = logging.getLogger("SENTINEL_MASTER_AGENT")


class MasterAgentPipeline(AnalyzerInterface):
    """Master agent that orchestrates comprehensive forensic analysis."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gpt-4",
        temperature: float = 0.7,
        max_tokens: int = 2048,
        use_orchestrator: bool = True,
        gpu_id: int = 0
    ):
        """
        Initialize Master Agent Pipeline.
        
        Args:
            api_key: OpenAI API key. Defaults to OPENAI_API_KEY env var
            model: OpenAI model to use (default: gpt-4)
            temperature: Temperature for model responses (0-1)
            max_tokens: Maximum tokens in response
            use_orchestrator: Use local orchestrator for initial analysis
            gpu_id: GPU device ID for local models
        """
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.client = None
        self.use_orchestrator = use_orchestrator
        self.gpu_id = gpu_id
        
        # Initialize local components
        self.orchestrator = ForensicOrchestrator(gpu_id=gpu_id) if use_orchestrator else None
        self.asset_analyzer = AssetAnalyzer()
        self.model_manager = ModelManager(gpu_id=gpu_id) if use_orchestrator else None
        
        self.validate()
        logger.info("MasterAgentPipeline initialized")

    def validate(self) -> bool:
        """
        Validate master agent configuration.
        OpenAI API key is optional (can use local models only).
        
        Returns:
            True if validation passes
            
        Raises:
            ValueError: If critical components fail
        """
        # OpenAI API is optional
        if self.api_key:
            try:
                self.client = OpenAI(api_key=self.api_key)
                self.client.models.list()
                logger.info("OpenAI API connection verified")
            except Exception as e:
                logger.warning(f"OpenAI API connection failed, will use local models only: {e}")
                self.client = None
        else:
            logger.info("No OpenAI API key, using local models only")
        
        # Verify local components
        if self.orchestrator:
            logger.info("Local orchestrator available")
        
        return True

    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Master analysis orchestration using both local and OpenAI models.
        
        Args:
            data: Input data containing:
                 {
                     "file_path": str,  # Path to file for analysis
                     "content": str,  # OR direct content for analysis
                     "context": str,  # Additional context/background
                     "task": str,  # Analysis task description
                     "force_local": bool,  # Force local-only analysis
                     "expect_json": bool  # Expect structured JSON response
                 }
        
        Returns:
            Dictionary with comprehensive analysis results
        """
        try:
            # Step 1: Determine analysis type (file vs content)
            file_path = data.get("file_path")
            content = data.get("content")
            context = data.get("context", "")
            task = data.get("task", "Perform comprehensive forensic analysis")
            force_local = data.get("force_local", False)
            expect_json = data.get("expect_json", True)

            result = {
                "status": "success",
                "timestamp": datetime.now().isoformat(),
                "analysis_components": {}
            }

            # Step 2: Local analysis if file path provided
            if file_path and self.orchestrator:
                logger.info(f"Starting comprehensive analysis of: {file_path}")
                
                local_result = self.orchestrator.orchestrate_analysis(
                    file_path,
                    force_reanalyze=False
                )
                
                result["analysis_components"]["local_forensics"] = local_result.to_dict()
                result["asset_metadata"] = {
                    "type": local_result.asset_metadata.asset_type.value,
                    "risk_level": local_result.asset_metadata.risk_level.value,
                    "suspicious": local_result.asset_metadata.is_suspicious,
                    "flags": local_result.asset_metadata.analysis_flags
                }

            # Step 3: OpenAI LLM synthesis (if available and not forced local)
            if self.client and not force_local:
                logger.info("Synthesizing analysis with OpenAI LLM")
                
                llm_synthesis = self._synthesize_with_openai(
                    data,
                    result.get("analysis_components", {}),
                    expect_json
                )
                
                result["analysis_components"]["llm_synthesis"] = llm_synthesis

            # Step 4: Generate final insights
            if result["analysis_components"]:
                result["final_insights"] = self._generate_final_insights(result)

            # Add metadata
            result["models_used"] = list(
                result.get("analysis_components", {}).keys()
            )
            result["full_context"] = context

            logger.info(f"Analysis completed successfully with {len(result['models_used'])} components")
            return result

        except Exception as e:
            logger.error(f"Analysis failed: {e}", exc_info=True)
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

    def _synthesize_with_openai(
        self,
        data: Dict[str, Any],
        local_results: Dict[str, Any],
        expect_json: bool = True
    ) -> Dict[str, Any]:
        """Synthesize findings using OpenAI LLM."""
        try:
            prompt = self._build_synthesis_prompt(data, local_results)
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": self._get_system_prompt()
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                response_format={"type": "json_object"} if expect_json else None
            )
            
            response_content = response.choices[0].message.content
            
            # Try to parse as JSON if expected
            if expect_json:
                try:
                    parsed = json.loads(response_content)
                    synthesis = parsed
                except json.JSONDecodeError:
                    synthesis = {"raw_analysis": response_content}
            else:
                synthesis = {"analysis": response_content}
            
            return {
                "status": "success",
                "model": self.model,
                "synthesis": synthesis,
                "usage": {
                    "prompt_tokens": response.usage.prompt_tokens,
                    "completion_tokens": response.usage.completion_tokens,
                    "total_tokens": response.usage.total_tokens
                }
            }

        except Exception as e:
            logger.error(f"OpenAI synthesis failed: {e}")
            return {
                "status": "error",
                "error": str(e)
            }

    def _get_system_prompt(self) -> str:
        """Get the system prompt for forensic analysis."""
        return """You are an expert multimedia forensic analyst AI system.

Your role is to:
1. Analyze digital evidence (images, videos, audio, documents, binaries)
2. Detect manipulations, deepfakes, anomalies, and suspicious activity
3. Extract and correlate forensic artifacts
4. Provide evidence-based risk assessments
5. Generate actionable recommendations for investigators

You have access to specialized models for:
- Computer Vision (object detection, deepfake detection, classification)
- Natural Language Processing (entity extraction, threat detection)
- Digital Forensics (binary analysis, metadata analysis)

Provide structured, detailed analysis with clear reasoning and evidence trails."""

    def _build_synthesis_prompt(
        self,
        data: Dict[str, Any],
        local_results: Dict[str, Any]
    ) -> str:
        """Build synthesis prompt for LLM."""
        file_path = data.get("file_path", "unknown")
        context = data.get("context", "")
        task = data.get("task", "")
        
        # Format local results for presentation
        local_summary = json.dumps(local_results, indent=2) if local_results else "No local analysis results"
        
        prompt = f"""
Forensic Analysis Request
========================

File/Asset: {file_path}
Task: {task}
Context: {context}

Local Analysis Results:
{local_summary}

Based on the above local forensic analysis results, provide:
1. Enhanced interpretation and pattern analysis
2. Cross-correlation of findings
3. Risk assessment and confidence levels
4. Specific fraud/manipulation indicators if applicable
5. Investigative recommendations
6. Confidence scores for each finding

Format your response as structured JSON with clear sections.
"""
        return prompt.strip()

    def _generate_final_insights(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate final consolidated insights from all analysis components."""
        key_findings = []
        risk_levels_seen = []
        confidence_scores = []

        # Extract findings from local forensics
        if "local_forensics" in result.get("analysis_components", {}):
            local = result["analysis_components"]["local_forensics"]
            if "findings" in local:
                key_findings.extend(local["findings"])
            # Collect risk data
            asset = result.get("asset_metadata", {})
            if asset.get("risk_level"):
                risk_levels_seen.append(asset["risk_level"])
            # Extract model confidences
            for model_name, model_result in local.get("model_results", {}).items():
                if isinstance(model_result, dict):
                    conf = model_result.get("confidence") or model_result.get("top_confidence")
                    if conf is not None:
                        confidence_scores.append(float(conf))
                    if model_result.get("status") == "success":
                        key_findings.append({
                            "source": model_name,
                            "type": "model_result",
                            "detail": {k: v for k, v in model_result.items() if k != "status"}
                        })

        # Extract insights from LLM synthesis
        if "llm_synthesis" in result.get("analysis_components", {}):
            llm = result["analysis_components"]["llm_synthesis"]
            if llm.get("status") == "success":
                synthesis = llm.get("synthesis", {})
                if isinstance(synthesis, dict):
                    # Merge LLM structured findings into insights
                    for k, v in synthesis.items():
                        if k not in ("summary", "key_findings", "risk_assessment", "confidence_level"):
                            key_findings.append({"source": "llm", "type": k, "detail": v})
                    if "key_findings" in synthesis:
                        key_findings.extend(synthesis["key_findings"] if isinstance(synthesis["key_findings"], list) else [])

        # Determine risk assessment
        risk_priority = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        if risk_levels_seen:
            highest_risk = max(risk_levels_seen, key=lambda r: risk_priority.get(r.upper(), 0))
        else:
            highest_risk = "UNKNOWN"

        # Determine confidence level
        if confidence_scores:
            avg_conf = sum(confidence_scores) / len(confidence_scores)
            if avg_conf > 0.8:
                confidence_label = "HIGH"
            elif avg_conf > 0.5:
                confidence_label = "MEDIUM"
            else:
                confidence_label = "LOW"
        else:
            confidence_label = "UNKNOWN"

        # Build summary from actual results
        components_count = len(result.get("analysis_components", {}))
        findings_count = len(key_findings)
        summary = (
            f"Forensic analysis completed using {components_count} component(s). "
            f"{findings_count} finding(s) identified. "
            f"Overall risk: {highest_risk}."
        )

        return {
            "summary": summary,
            "key_findings": key_findings,
            "risk_assessment": highest_risk,
            "confidence_level": confidence_label,
            "findings_count": findings_count,
            "average_confidence": round(avg_conf, 4) if confidence_scores else None,
        }

    def batch_analyze(
        self,
        file_paths: List[str],
        context: str = ""
    ) -> List[Dict[str, Any]]:
        """
        Analyze multiple files sequentially.
        
        Args:
            file_paths: List of file paths to analyze
            context: Shared context for the batch
            
        Returns:
            List of analysis results
        """
        results = []
        logger.info(f"Starting batch analysis of {len(file_paths)} files")
        
        for file_path in file_paths:
            try:
                result = self.analyze({
                    "file_path": file_path,
                    "context": context,
                    "task": f"Analyze for tampering, deepfakes, and anomalies"
                })
                results.append(result)
            except Exception as e:
                logger.error(f"Batch analysis failed for {file_path}: {e}")
                results.append({
                    "status": "error",
                    "file_path": file_path,
                    "error": str(e)
                })
        
        logger.info(f"Batch analysis complete. Processed {len(results)} files")
        return results

    def set_model(self, model: str) -> None:
        """
        Update the OpenAI model to use.
        
        Args:
            model: Model identifier (e.g., 'gpt-4', 'gpt-3.5-turbo')
        """
        self.model = model
        logger.info(f"Model set to {model}")

    def set_temperature(self, temperature: float) -> None:
        """
        Update temperature for model responses.
        
        Args:
            temperature: Value between 0 and 1
        """
        if not 0 <= temperature <= 1:
            raise ValueError("Temperature must be between 0 and 1")
        self.temperature = temperature
        logger.info(f"Temperature set to {temperature}")

    def set_max_tokens(self, max_tokens: int) -> None:
        """
        Update maximum tokens in response.
        
        Args:
            max_tokens: Maximum number of tokens
        """
        if max_tokens < 1:
            raise ValueError("Max tokens must be at least 1")
        self.max_tokens = max_tokens
        logger.info(f"Max tokens set to {max_tokens}")

    def get_system_info(self) -> Dict[str, Any]:
        """Get system and model information."""
        info = {
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "openai_api_available": self.client is not None,
            "local_orchestrator_available": self.orchestrator is not None
        }
        
        if self.model_manager:
            info["system_info"] = self.model_manager.get_system_info()
            info["available_models"] = list(
                self.model_manager.get_model_registry().keys()
            )
        
        return info
