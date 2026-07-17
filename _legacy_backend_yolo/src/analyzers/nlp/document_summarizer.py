"""
Document Summarizer Module
Generates forensic case summaries using HuggingFace transformers (BART).
Optimized for large files with smart chunking. Runs locally.
"""

import logging
import re
import gc
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict

logger = logging.getLogger("SENTINEL_SUMMARIZER")


@dataclass
class CaseSummary:
    """Structured forensic case summary."""
    executive_summary: str
    key_findings: List[str]
    entities_mentioned: List[str]
    risk_assessment: str
    document_type: str
    word_count: int
    
    def to_dict(self) -> Dict:
        return asdict(self)


class DocumentSummarizer:
    """
    Generates forensic case summaries using BART or T5 models.
    Handles large documents with overlapping chunking and hierarchical merging.
    """
    
    MAX_FILE_CHARS = 500_000  # 500K chars max per file (~100K words)
    
    DOC_TYPE_PATTERNS = {
        'chat_log': ['sent:', 'received:', 'user:', 'message:', 'chat', 'dm', 'conversation'],
        'email': ['from:', 'to:', 'subject:', 'dear', 'regards', 'sincerely', 'attached'],
        'incident_report': ['incident', 'report', 'investigation', 'officer', 'victim', 'suspect', 'evidence'],
        'financial_record': ['transaction', 'account', 'balance', 'payment', 'invoice', 'wire transfer'],
        'legal_document': ['court', 'plaintiff', 'defendant', 'hearing', 'statute', 'jurisdiction'],
        'general': []
    }
    
    def __init__(
        self,
        model_name: str = "facebook/bart-large-cnn",
        max_chunk_tokens: int = 1024,
        overlap_tokens: int = 100,
        use_gpu: bool = False
    ):
        self.model_name = model_name
        self.max_chunk_tokens = max_chunk_tokens
        self.overlap_tokens = overlap_tokens
        self.use_gpu = use_gpu
        self.summarizer = None
        self._initialized = False
    
    def initialize(self) -> bool:
        """Load the summarization model."""
        try:
            from transformers import pipeline
            import torch
            
            device = 0 if (self.use_gpu and torch.cuda.is_available()) else -1
            
            self.summarizer = pipeline(
                "summarization",
                model=self.model_name,
                device=device,
                truncation=True
            )
            
            self._initialized = True
            logger.info(f"Summarizer loaded: {self.model_name}")
            return True
            
        except Exception as e:
            logger.warning(f"Model load failed ({e}). Using extractive fallback.")
            self._initialized = True
            return True
    
    def summarize(self, text: str, filename: str = "") -> CaseSummary:
        """Generate a forensic case summary."""
        if not self._initialized:
            self.initialize()
        
        if not text or not text.strip():
            return CaseSummary(
                executive_summary="No content to summarize.",
                key_findings=[], entities_mentioned=[],
                risk_assessment="N/A", document_type="empty", word_count=0
            )
        
        # Truncate very large files to prevent memory issues
        if len(text) > self.MAX_FILE_CHARS:
            logger.info(f"Truncating file from {len(text)} to {self.MAX_FILE_CHARS} chars")
            text = text[:self.MAX_FILE_CHARS]
        
        word_count = len(text.split())
        doc_type = self._detect_document_type(text, filename)
        entities = self._extract_entities(text)
        
        # Generate summary
        if self.summarizer:
            summary_text = self._generate_model_summary(text)
        else:
            summary_text = self._generate_extractive_summary(text)
        
        # Post-process for better readability
        summary_text = self._structure_summary(summary_text, text, doc_type)
        
        key_findings = self._extract_key_findings(text, summary_text)
        risk = self._assess_risk(text, key_findings)
        
        return CaseSummary(
            executive_summary=summary_text,
            key_findings=key_findings,
            entities_mentioned=entities,
            risk_assessment=risk,
            document_type=doc_type,
            word_count=word_count
        )
    
    def _generate_model_summary(self, text: str) -> str:
        """Generate summary using BART with smart chunking for large docs."""
        try:
            clean = self._clean_text(text)
            words = clean.split()
            
            if len(words) < 50:
                return clean
            
            if len(words) <= self.max_chunk_tokens:
                result = self.summarizer(
                    clean, max_length=250, min_length=50, do_sample=False
                )
                return result[0]['summary_text']
            
            return self._hierarchical_summarize(clean)
            
        except Exception as e:
            logger.error(f"Model summarization failed: {e}")
            return self._generate_extractive_summary(text)
    
    def _hierarchical_summarize(self, text: str) -> str:
        """Overlapping chunk summarization with hierarchical merging for large files."""
        words = text.split()
        chunk_size = self.max_chunk_tokens
        overlap = self.overlap_tokens
        
        chunks = []
        start = 0
        while start < len(words):
            end = min(start + chunk_size, len(words))
            chunk = ' '.join(words[start:end])
            if len(chunk.split()) >= 40:
                chunks.append(chunk)
            start += chunk_size - overlap
        
        max_chunks = 10
        if len(chunks) > max_chunks:
            step = len(chunks) / max_chunks
            chunks = [chunks[int(i * step)] for i in range(max_chunks)]
        
        level1_summaries = []
        for i, chunk in enumerate(chunks):
            try:
                result = self.summarizer(
                    chunk, max_length=130, min_length=30, do_sample=False
                )
                level1_summaries.append(result[0]['summary_text'])
            except Exception as e:
                logger.debug(f"Chunk {i+1} failed: {e}")
                level1_summaries.append(self._extract_top_sentences(chunk, 2))
            gc.collect()
        
        if not level1_summaries:
            return self._generate_extractive_summary(text)
        
        merged = ' '.join(level1_summaries)
        
        if len(merged.split()) > 300 and self.summarizer:
            try:
                result = self.summarizer(
                    merged, max_length=300, min_length=80, do_sample=False
                )
                return result[0]['summary_text']
            except:
                pass
        
        return merged
    
    def _generate_extractive_summary(self, text: str, num_sentences: int = 6) -> str:
        """Extractive fallback using forensic keyword scoring."""
        sentences = re.split(r'(?<=[.!?])\s+', text)
        sentences = [s.strip() for s in sentences if len(s.strip()) > 20]
        
        if not sentences:
            return text[:500]
        
        forensic_keywords = [
            'suspect', 'victim', 'evidence', 'found', 'detected', 'identified',
            'money', 'transfer', 'account', 'weapon', 'drug', 'attack',
            'investigation', 'report', 'incident', 'breach', 'stolen',
            'criminal', 'fraud', 'threat', 'unauthorized', 'suspicious',
            'arrested', 'witness', 'confession', 'warrant', 'seizure'
        ]
        
        scored = []
        for idx, s in enumerate(sentences):
            score = sum(1 for kw in forensic_keywords if kw in s.lower())
            if idx < 3:
                score += 2
            if idx >= len(sentences) - 2:
                score += 1
            scored.append((idx, score, s))
        
        scored.sort(key=lambda x: x[1], reverse=True)
        top = sorted(scored[:num_sentences], key=lambda x: x[0])
        
        return '. '.join(t[2].rstrip('.') for t in top) + '.'
    
    def _extract_top_sentences(self, text: str, n: int = 2) -> str:
        """Quick extraction of top N sentences."""
        sentences = re.split(r'(?<=[.!?])\s+', text)
        sentences = [s.strip() for s in sentences if len(s.strip()) > 15]
        return '. '.join(sentences[:n]) + '.' if sentences else text[:200]
    
    def _detect_document_type(self, text: str, filename: str = "") -> str:
        text_lower = text[:5000].lower()
        filename_lower = filename.lower()
        
        best_type, best_score = 'general', 0
        for doc_type, patterns in self.DOC_TYPE_PATTERNS.items():
            if doc_type == 'general':
                continue
            score = sum(1 for p in patterns if p in text_lower or p in filename_lower)
            if score > best_score:
                best_score = score
                best_type = doc_type
        
        return best_type if best_score >= 2 else 'general'
    
    def _extract_entities(self, text: str) -> List[str]:
        """Extract forensic entities via regex."""
        entities = set()
        scan_text = text[:50000]
        
        entities.update(re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', scan_text)[:5])
        entities.update(re.findall(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', scan_text)[:5])
        entities.update(re.findall(r'\$[\d,]+(?:\.\d{2})?', scan_text)[:5])
        entities.update(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', scan_text)[:5])
        entities.update(re.findall(r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b', scan_text)[:5])
        entities.update(re.findall(r'\b[A-Z][a-z]+ [A-Z][a-z]+\b', scan_text)[:8])
        entities.update(re.findall(r'https?://\S+', scan_text)[:3])
        
        return sorted(list(entities))[:20]
    
    def _extract_key_findings(self, text: str, summary: str) -> List[str]:
        findings = []
        text_lower = text[:30000].lower()
        
        indicators = {
            'Financial transactions detected': ['wire transfer', 'payment', 'transaction', 'bitcoin', 'account'],
            'Communication records found': ['chat', 'message', 'email', 'conversation', 'sent', 'received'],
            'Criminal activity indicators': ['drug', 'weapon', 'attack', 'threat', 'ransom', 'hack'],
            'Personal data exposure': ['ssn', 'social security', 'credit card', 'passport', 'license'],
            'Cyber threat indicators': ['malware', 'ransomware', 'phishing', 'breach', 'exploit', 'botnet'],
            'Fraud indicators': ['fraud', 'launder', 'embezzle', 'counterfeit', 'forge', 'scheme'],
            'Violence-related content': ['kill', 'assault', 'weapon', 'bomb', 'shoot', 'threat'],
            'Identity-related data': ['identity', 'impersonate', 'fake id', 'stolen identity'],
            'Location data found': ['gps', 'coordinates', 'latitude', 'longitude', 'geolocation'],
            'Timestamp evidence': ['timestamp', 'logged at', 'accessed on', 'modified on']
        }
        
        for finding, keywords in indicators.items():
            matched = [kw for kw in keywords if kw in text_lower]
            if matched:
                findings.append(f"{finding} ({', '.join(matched[:3])})")
        
        return findings
    
    def _assess_risk(self, text: str, findings: List[str]) -> str:
        if len(findings) >= 5:
            return "CRITICAL"
        elif len(findings) >= 3:
            return "HIGH"
        elif len(findings) >= 2:
            return "MEDIUM"
        elif len(findings) >= 1:
            return "LOW"
        return "MINIMAL"
    
    def _structure_summary(self, summary: str, full_text: str, doc_type: str) -> str:
        """Post-process summary to add structure and improve readability."""
        if len(summary.split()) < 20:
            return summary
        
        sentences = summary.split('. ')
        structured_parts = []
        
        type_intro = {
            'email': 'This email communication',
            'chat_log': 'This conversation',
            'incident_report': 'This incident report',
            'financial_record': 'This financial document',
            'legal_document': 'This legal document',
            'general': 'This document'
        }
        intro = type_intro.get(doc_type, 'This document')
        
        what_info = []
        who_info = []
        when_where_info = []
        
        for sent in sentences:
            sent_lower = sent.lower()
            if any(word in sent_lower for word in ['contains', 'describes', 'presents', 'discusses', 'details', 'shows', 'reveals']):
                what_info.append(sent.strip())
            elif any(word in sent_lower for word in ['team', 'person', 'user', 'suspect', 'victim', 'company', 'organization']):
                who_info.append(sent.strip())
            elif any(word in sent_lower for word in ['date', 'time', 'location', 'place', 'when', 'where', 'during']):
                when_where_info.append(sent.strip())
            else:
                what_info.append(sent.strip())
        
        if what_info:
            structured_parts.append(f"{intro} {what_info[0].lower() if what_info[0] else 'contains information'}.")
        
        remaining = what_info[1:] + who_info + when_where_info
        if remaining:
            for item in remaining[:3]:
                if item and len(item) > 10:
                    structured_parts.append(item.strip() + ('.' if not item.endswith('.') else ''))
        
        result = ' '.join(structured_parts)
        if len(result.split()) < 15:
            return summary
        
        return result
    
    def _clean_text(self, text: str) -> str:
        text = re.sub(r'\s+', ' ', text)
        lines = text.split('\n')
        lines = [l for l in lines if len(l.strip()) > 10]
        return ' '.join(lines).strip()
    
    def cleanup(self):
        self.summarizer = None
        self._initialized = False
        gc.collect()
        logger.info("Summarizer resources released")

