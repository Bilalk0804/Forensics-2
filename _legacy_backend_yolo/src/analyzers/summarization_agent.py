"""
Summarization Agent Module
Uses Google API for content retrieval and OpenAI SDK for intelligent summarization.
Integrates with forensic analysis for case summary generation.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional
from datetime import datetime

try:
    import google.generativeai as genai
    GOOGLE_AVAILABLE = True
except ImportError:
    GOOGLE_AVAILABLE = False

from .interface import AnalyzerInterface

logger = logging.getLogger("SENTINEL_SUMMARIZATION")


class SummarizationAgent(AnalyzerInterface):
    """
    Summarization agent for forensic case analysis.
    
    Uses:
    - Google API for document retrieval and enhancement
    - OpenAI SDK for intelligent summarization
    
    Lifecycle:
        agent = SummarizationAgent(
            openai_api_key="...",
            google_api_key="..."
        )
        agent.validate()
        summary = agent.summarize_case(case_data)
    """

    def __init__(
        self,
        google_api_key: Optional[str] = None,
        temperature: float = 0.5,
        max_tokens: int = 2000,
        db: Optional[Any] = None
    ):
        """
        Initialize Summarization Agent (Google Generative AI only).

        Args:
            google_api_key: Google API key (defaults to GOOGLE_API_KEY env var)
            temperature: Creativity level (0-1, lower = more factual)
            max_tokens: Maximum response length
            db: Database handler for storing summaries
        """
        self.google_api_key = google_api_key or os.getenv("GOOGLE_API_KEY")
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.db = db

        # Initialize client
        self.google_client = None
        self.is_ready = False

    # ------------------------------------------------------------------
    # AnalyzerInterface implementation
    # ------------------------------------------------------------------

    def validate(self) -> bool:
        """
        Validate that Google Generative AI is available.

        Returns:
            True if validation passes

        Raises:
            ImportError: if required packages are missing
        """
        if not GOOGLE_AVAILABLE:
            logger.error("Google Generative AI library not available")
            return False

        # Try to initialize Google client
        if self.google_api_key:
            try:
                genai.configure(api_key=self.google_api_key)
                # Use gemini-2.0-flash for better performance, fall back to gemini-pro
                try:
                    self.google_client = genai.GenerativeModel('gemini-2.0-flash')
                except Exception:
                    logger.info("gemini-2.0-flash not available, trying gemini-1.5-pro")
                    try:
                        self.google_client = genai.GenerativeModel('gemini-1.5-pro')
                    except Exception:
                        logger.warning("No suitable Gemini model available; using gemini-pro")
                        self.google_client = genai.GenerativeModel('gemini-pro')
                logger.info("Google Generative AI (Gemini Pro) client initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize Google client: {e}")
                self.google_client = None
                return False
        else:
            logger.error("Google API key not provided")
            return False

        self.is_ready = True
        logger.info("Summarization agent validation passed")
        return True

    def analyze(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform analysis - wrapper for summarization.

        Args:
            data: Data to analyze

        Returns:
            Analysis results
        """
        return self.summarize_case(data)

    # ------------------------------------------------------------------
    # Core Summarization Methods
    # ------------------------------------------------------------------

    def summarize_case(self, case_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive forensic case summary.

        Args:
            case_data: Dictionary containing case findings, artifacts, risks

        Returns:
            Dictionary with executive summary, key findings, recommendations
        """
        if not self.is_ready:
            if not self.validate():
                logger.error("Summarization agent not ready")
                return {"error": "Agent not initialized"}

        try:
            # Prepare case summary structure
            summary_result = {
                "timestamp": datetime.now().isoformat(),
                "executive_summary": "",
                "key_findings": [],
                "risk_assessment": "",
                "object_detections": [],
                "malware_threats": [],
                "recommendations": [],
                "confidence_level": 0.0,
                "analysis_metadata": {}
            }

            # Extract and organize data from case
            case_text = self._prepare_case_text(case_data)

            # Generate summary using Google API
            if self.google_client:
                summary_result = self._summarize_with_google(case_text, summary_result)

            # Store in database if available
            if self.db:
                self._store_summary(summary_result)

            logger.info("Case summarization completed successfully")
            return summary_result

        except Exception as e:
            logger.error(f"Case summarization failed: {e}", exc_info=True)
            return {"error": str(e)}

    def summarize_findings(
        self,
        findings: List[Dict[str, Any]],
        summary_type: str = "technical"
    ) -> str:
        """
        Summarize specific forensic findings.

        Args:
            findings: List of finding dictionaries
            summary_type: Type of summary ('technical', 'executive', 'legal')

        Returns:
            Summarized findings text
        """
        if not self.google_client:
            logger.warning("Google API not available for findings summarization")
            return ""

        try:
            findings_text = json.dumps(findings, indent=2)

            prompts = {
                "technical": f"""Summarize these forensic findings in technical detail:
{findings_text}

Include: detection methods, confidence levels, technical indicators, and analysis depth.""",

                "executive": f"""Create an executive summary of these forensic findings:
{findings_text}

Focus on: impact, severity, clear language for non-technical readers, action items.""",

                "legal": f"""Generate a legally sound summary of forensic findings:
{findings_text}

Include: chain of custody, evidence integrity, admissibility notes, professional disclaimers."""
            }

            prompt = prompts.get(summary_type, prompts["technical"])

            response = self.google_client.generate_content(prompt)
            return response.text

        except Exception as e:
            logger.error(f"Findings summarization failed: {e}")
            return ""

    def generate_recommendations(
        self,
        risk_level: str,
        threats: List[str],
        context: Dict[str, Any]
    ) -> List[str]:
        """
        Generate actionable security recommendations based on findings.

        Args:
            risk_level: Overall risk level (HIGH, MEDIUM, LOW)
            threats: List of detected threats
            context: Additional context about the system

        Returns:
            List of recommendations
        """
        if not self.google_client:
            logger.warning("Google API not available for recommendations")
            return []

        try:
            context_str = json.dumps(context, indent=2)
            threats_str = "\n- ".join(threats)

            prompt = f"""Generate security recommendations for this forensic case:

Risk Level: {risk_level}
Detected Threats:
- {threats_str}

Context:
{context_str}

Provide:
1. Immediate actions (next 24-48 hours)
2. Short-term remediation (1-2 weeks)
3. Long-term improvements (ongoing)
4. Compliance/legal considerations

Format as a numbered list with clear action items."""

            response = self.google_client.generate_content(prompt)
            content = response.text
            
            # Parse recommendations from response
            recommendations = [line.strip() for line in content.split('\n') if line.strip()]
            return recommendations

        except Exception as e:
            logger.error(f"Recommendation generation failed: {e}")
            return []

    # ------------------------------------------------------------------
    # Private Helper Methods
    # ------------------------------------------------------------------

    def _prepare_case_text(self, case_data: Dict[str, Any]) -> str:
        """
        Convert case data into readable text format for summarization.

        Args:
            case_data: Case data dictionary

        Returns:
            Formatted case text
        """
        parts = []

        # Case metadata
        if "case_id" in case_data:
            parts.append(f"Case ID: {case_data['case_id']}")
        if "timestamp" in case_data:
            parts.append(f"Analysis Date: {case_data['timestamp']}")

        # Summary of findings by type
        if "vision_findings" in case_data:
            parts.append("\n=== VISION ANALYSIS (YOLO) ===")
            findings = case_data["vision_findings"]
            if isinstance(findings, list):
                for finding in findings[:5]:  # Limit to top 5
                    if isinstance(finding, dict):
                        parts.append(f"- {finding.get('object', 'Unknown')}: {finding.get('risk', 'N/A')}")

        if "malware_findings" in case_data:
            parts.append("\n=== MALWARE DETECTION ===")
            findings = case_data["malware_findings"]
            if isinstance(findings, list):
                for finding in findings[:5]:
                    if isinstance(finding, dict):
                        parts.append(f"- {finding.get('file', 'Unknown')}: {finding.get('status', 'N/A')}")

        if "text_findings" in case_data:
            parts.append("\n=== TEXT/NLP ANALYSIS ===")
            text = case_data["text_findings"]
            if isinstance(text, str):
                parts.append(text[:500])  # Limit text

        if "image_findings" in case_data:
            parts.append("\n=== IMAGE ANALYSIS ===")
            findings = case_data["image_findings"]
            if isinstance(findings, list):
                for finding in findings[:5]:
                    if isinstance(finding, dict):
                        parts.append(f"- {finding.get('classification', 'Unknown')}: confidence {finding.get('confidence', 'N/A')}")

        if "risk_summary" in case_data:
            parts.append(f"\n=== RISK SUMMARY ===\n{case_data['risk_summary']}")

        return "\n".join(parts)

    def _summarize_with_google(
        self,
        case_text: str,
        summary_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate summary using Google Generative AI.

        Args:
            case_text: Formatted case text
            summary_result: Result dictionary to update

        Returns:
            Updated result dictionary
        """
        try:
            # Executive summary
            exec_prompt = f"""Provide a concise 2-3 sentence executive summary:

{case_text}

Focus: main findings and immediate risk."""

            exec_response = self.google_client.generate_content(exec_prompt)
            summary_result["executive_summary"] = exec_response.text

            # Key findings
            findings_prompt = f"""Extract the top 5 key findings:

{case_text}

Format: numbered list."""

            findings_response = self.google_client.generate_content(findings_prompt)
            findings_text = findings_response.text
            summary_result["key_findings"] = [
                line.strip() for line in findings_text.split('\n')
                if line.strip()
            ]

            logger.info("Google summarization completed")

        except Exception as e:
            logger.error(f"Google summarization failed: {e}")

        return summary_result

    def _store_summary(self, summary_result: Dict[str, Any]):
        """Store summary in database."""
        try:
            if not self.db:
                return

            conn = self.db.get_connection()
            cursor = conn.cursor()

            # Store summary as artifact
            cursor.execute('''
                INSERT INTO artifacts (file_id, pipeline_name, risk_level, description, metadata)
                VALUES (NULL, ?, ?, ?, ?)
            ''', (
                "summarization_agent",
                self._extract_risk_level(summary_result.get("risk_assessment", "")),
                "Case Summary",
                json.dumps(summary_result)
            ))
            conn.commit()
            conn.close()
            logger.info("Summary stored in database")

        except Exception as e:
            logger.error(f"Failed to store summary: {e}")

    def _extract_risk_level(self, risk_text: str) -> str:
        """Extract risk level from assessment text."""
        risk_text_upper = risk_text.upper()
        if "HIGH" in risk_text_upper:
            return "HIGH"
        elif "MEDIUM" in risk_text_upper or "MODERATE" in risk_text_upper:
            return "MEDIUM"
        else:
            return "LOW"
