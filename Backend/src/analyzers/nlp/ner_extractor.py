"""
Named Entity Recognition (NER) Extractor Module
Uses transformer models (BERT/RoBERTa) to extract entities from text.
"""

import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger("SENTINEL_NER")


@dataclass
class Entity:
    """Represents an extracted named entity."""
    text: str
    entity_type: str
    start: int
    end: int
    confidence: float
    context: str = ""


class NERExtractor:
    """
    Named Entity Recognition using transformer models.
    Extracts: PERSON, ORG, GPE, MONEY, DATE, PHONE, EMAIL, ADDRESS
    """
    
    # Entity types considered sensitive for forensics
    SENSITIVE_ENTITY_TYPES = {
        'PERSON': 'medium',
        'ORG': 'medium', 
        'GPE': 'low',  # Geopolitical Entity (locations)
        'MONEY': 'high',
        'DATE': 'low',
        'CARDINAL': 'low',
        'PHONE': 'high',
        'EMAIL': 'high',
        'ADDRESS': 'high',
        'CREDIT_CARD': 'critical',
        'SSN': 'critical',
        'BANK_ACCOUNT': 'critical',
    }
    
    def __init__(self, model_name: str = "dslim/bert-base-NER", use_gpu: bool = True):
        """
        Initialize NER extractor.
        
        Args:
            model_name: HuggingFace model name for NER
            use_gpu: Whether to use GPU acceleration
        """
        self.model_name = model_name
        self.use_gpu = use_gpu
        self.pipeline = None
        self._initialized = False
        
    def initialize(self) -> bool:
        """Load the NER model. Call this before extraction."""
        try:
            from transformers import pipeline
            import torch
            
            device = 0 if self.use_gpu and torch.cuda.is_available() else -1
            
            self.pipeline = pipeline(
                "ner",
                model=self.model_name,
                aggregation_strategy="simple",
                device=device
            )
            
            self._initialized = True
            logger.info(f"NER model loaded: {self.model_name} (GPU: {device >= 0})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize NER model: {e}")
            return False
    
    def extract_entities(self, text: str, context_window: int = 50) -> List[Entity]:
        """
        Extract named entities from text.
        
        Args:
            text: Input text to analyze
            context_window: Characters of context to include around each entity
            
        Returns:
            List of Entity objects
        """
        if not self._initialized:
            if not self.initialize():
                return []
        
        if not text or not text.strip():
            return []
            
        try:
            # Run NER pipeline
            raw_entities = self.pipeline(text)
            
            entities = []
            for ent in raw_entities:
                # Extract context around entity
                start = max(0, ent['start'] - context_window)
                end = min(len(text), ent['end'] + context_window)
                context = text[start:end]
                
                entity = Entity(
                    text=ent['word'],
                    entity_type=ent['entity_group'],
                    start=ent['start'],
                    end=ent['end'],
                    confidence=float(ent['score']),
                    context=context
                )
                entities.append(entity)
            
            # Also run regex patterns for additional sensitive data
            entities.extend(self._extract_patterns(text, context_window))
            
            logger.debug(f"Extracted {len(entities)} entities from text")
            return entities
            
        except Exception as e:
            logger.error(f"Entity extraction failed: {e}")
            return []
    
    def _extract_patterns(self, text: str, context_window: int) -> List[Entity]:
        """Extract entities using regex patterns for common sensitive data."""
        import re
        
        patterns = {
            'EMAIL': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'PHONE': r'(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}',
            'CREDIT_CARD': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
            'SSN': r'\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b',
            'IP_ADDRESS': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        }
        
        entities = []
        for entity_type, pattern in patterns.items():
            for match in re.finditer(pattern, text):
                start = max(0, match.start() - context_window)
                end = min(len(text), match.end() + context_window)
                
                entity = Entity(
                    text=match.group(),
                    entity_type=entity_type,
                    start=match.start(),
                    end=match.end(),
                    confidence=0.95,  # High confidence for regex matches
                    context=text[start:end]
                )
                entities.append(entity)
        
        return entities
    
    def get_risk_level(self, entity_type: str) -> str:
        """Get risk level for an entity type."""
        return self.SENSITIVE_ENTITY_TYPES.get(entity_type, 'low')
    
    def cleanup(self):
        """Release model resources."""
        self.pipeline = None
        self._initialized = False
        logger.info("NER model unloaded")
