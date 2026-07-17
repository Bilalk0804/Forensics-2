"""
Text Evidence Extractor - Main Orchestrator
Combines NER, Topic Modeling, and Keyword Search for comprehensive text analysis.
"""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

from .ner_extractor import NERExtractor, Entity
from .topic_modeler import TopicModeler, Topic
from .keyword_searcher import KeywordSearcher, KeywordMatch

logger = logging.getLogger("SENTINEL_TEXT_EVIDENCE")


@dataclass
class TextEvidence:
    """Represents extracted text evidence."""
    evidence_type: str  # 'NER', 'TOPIC', 'KEYWORD'
    entity_type: str
    entity_value: str
    confidence: float
    context: str
    risk_level: str
    category: str = ""
    metadata: Dict = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for database storage."""
        return asdict(self)


class TextEvidenceExtractor:
    """
    Main orchestrator for textual evidence extraction.
    Runs NER → Topic Modeling → Keyword Search pipeline.
    """
    
    def __init__(
        self,
        use_gpu: bool = True,
        ner_model: str = "dslim/bert-base-NER",
        enable_ner: bool = True,
        enable_topics: bool = True,
        enable_keywords: bool = True
    ):
        """
        Initialize the text evidence extractor.
        
        Args:
            use_gpu: Use GPU acceleration for NER
            ner_model: HuggingFace NER model name
            enable_ner: Enable NER extraction
            enable_topics: Enable topic modeling  
            enable_keywords: Enable keyword search
        """
        self.use_gpu = use_gpu
        self.enable_ner = enable_ner
        self.enable_topics = enable_topics
        self.enable_keywords = enable_keywords
        
        # Initialize components
        self.ner = NERExtractor(model_name=ner_model, use_gpu=use_gpu) if enable_ner else None
        self.topic_modeler = TopicModeler() if enable_topics else None
        self.keyword_searcher = KeywordSearcher() if enable_keywords else None
        
        self._initialized = False
        
    def initialize(self) -> bool:
        """Initialize all enabled components."""
        try:
            if self.ner:
                if not self.ner.initialize():
                    logger.warning("NER initialization failed, continuing without NER")
                    self.enable_ner = False
            
            if self.topic_modeler:
                if not self.topic_modeler.initialize():
                    logger.warning("Topic modeler initialization failed, continuing without topics")
                    self.enable_topics = False
            
            # Keyword searcher doesn't need initialization
            
            self._initialized = True
            logger.info("TextEvidenceExtractor initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize TextEvidenceExtractor: {e}")
            return False
    
    def extract_evidence(
        self,
        text: str,
        file_id: Optional[int] = None,
        document_corpus: List[str] = None
    ) -> List[TextEvidence]:
        """
        Extract all types of evidence from text.
        
        Args:
            text: Text to analyze
            file_id: Optional file ID for tracking
            document_corpus: Optional corpus for better topic modeling
            
        Returns:
            List of TextEvidence objects
        """
        if not self._initialized:
            if not self.initialize():
                logger.error("Failed to initialize extractor")
                return []
        
        if not text or not text.strip():
            return []
        
        all_evidence = []
        
        # 1. Named Entity Recognition
        if self.enable_ner:
            try:
                entities = self.ner.extract_entities(text)
                for entity in entities:
                    evidence = TextEvidence(
                        evidence_type='NER',
                        entity_type=entity.entity_type,
                        entity_value=entity.text,
                        confidence=entity.confidence,
                        context=entity.context,
                        risk_level=self.ner.get_risk_level(entity.entity_type),
                        category='entity',
                        metadata={'start': entity.start, 'end': entity.end}
                    )
                    all_evidence.append(evidence)
                logger.debug(f"NER extracted {len(entities)} entities")
            except Exception as e:
                logger.error(f"NER extraction failed: {e}")
        
        # 2. Topic Modeling
        if self.enable_topics:
            try:
                topic_results = self.topic_modeler.analyze_single_document(
                    text, 
                    document_corpus
                )
                for topic, probability in topic_results:
                    evidence = TextEvidence(
                        evidence_type='TOPIC',
                        entity_type='topic',
                        entity_value=', '.join(topic.keywords[:5]),
                        confidence=probability,
                        context=f"Topic #{topic.topic_id}: {topic.category}",
                        risk_level=topic.risk_level,
                        category=topic.category,
                        metadata={'topic_id': topic.topic_id, 'weight': topic.weight}
                    )
                    all_evidence.append(evidence)
                logger.debug(f"Topic modeling found {len(topic_results)} relevant topics")
            except Exception as e:
                logger.error(f"Topic modeling failed: {e}")
        
        # 3. Keyword Search
        if self.enable_keywords:
            try:
                matches = self.keyword_searcher.search(text)
                for match in matches:
                    evidence = TextEvidence(
                        evidence_type='KEYWORD',
                        entity_type='keyword',
                        entity_value=match.matched_text,
                        confidence=match.confidence,
                        context=match.context,
                        risk_level=match.risk_level,
                        category=match.category,
                        metadata={
                            'keyword': match.keyword,
                            'start': match.start,
                            'end': match.end
                        }
                    )
                    all_evidence.append(evidence)
                logger.debug(f"Keyword search found {len(matches)} matches")
            except Exception as e:
                logger.error(f"Keyword search failed: {e}")
        
        # Sort by risk level
        risk_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        all_evidence.sort(key=lambda e: risk_order.get(e.risk_level, 4))
        
        logger.info(f"Total evidence extracted: {len(all_evidence)}")
        return all_evidence
    
    def get_risk_summary(self, evidence_list: List[TextEvidence]) -> Dict[str, Any]:
        """
        Generate a risk summary from extracted evidence.
        
        Args:
            evidence_list: List of TextEvidence objects
            
        Returns:
            Risk summary dictionary
        """
        if not evidence_list:
            return {
                'overall_risk': 'low',
                'total_evidence': 0,
                'by_type': {},
                'by_risk': {},
                'high_priority_items': []
            }
        
        by_type = {'NER': 0, 'TOPIC': 0, 'KEYWORD': 0}
        by_risk = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        high_priority = []
        
        for evidence in evidence_list:
            by_type[evidence.evidence_type] = by_type.get(evidence.evidence_type, 0) + 1
            by_risk[evidence.risk_level] = by_risk.get(evidence.risk_level, 0) + 1
            
            if evidence.risk_level in ('critical', 'high'):
                high_priority.append({
                    'type': evidence.evidence_type,
                    'value': evidence.entity_value,
                    'risk': evidence.risk_level,
                    'category': evidence.category
                })
        
        # Determine overall risk
        if by_risk['critical'] > 0:
            overall_risk = 'critical'
        elif by_risk['high'] >= 3:
            overall_risk = 'high'
        elif by_risk['high'] > 0 or by_risk['medium'] >= 5:
            overall_risk = 'medium'
        else:
            overall_risk = 'low'
        
        return {
            'overall_risk': overall_risk,
            'total_evidence': len(evidence_list),
            'by_type': by_type,
            'by_risk': by_risk,
            'high_priority_items': high_priority[:10]  # Top 10
        }
    
    def cleanup(self):
        """Release resources."""
        if self.ner:
            self.ner.cleanup()
        self._initialized = False
        logger.info("TextEvidenceExtractor resources released")
