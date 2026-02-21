"""
Topic Modeling Module
Uses LDA (Latent Dirichlet Allocation) to identify document themes.
"""

import logging
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from collections import Counter

logger = logging.getLogger("SENTINEL_TOPIC")


@dataclass
class Topic:
    """Represents a discovered topic."""
    topic_id: int
    keywords: List[str]
    weight: float
    category: str = "general"
    risk_level: str = "low"


class TopicModeler:
    """
    Topic modeling using LDA to identify document themes.
    Flags suspicious topic clusters for forensic analysis.
    """
    
    # Suspicious topic categories with associated keywords
    SUSPICIOUS_CATEGORIES = {
        'financial_fraud': [
            'money', 'transfer', 'account', 'bank', 'wire', 'payment',
            'cash', 'bitcoin', 'crypto', 'launder', 'offshore', 'tax',
            'invoice', 'fraud', 'scheme', 'embezzle'
        ],
        'violence': [
            'kill', 'attack', 'weapon', 'gun', 'bomb', 'threat',
            'harm', 'assault', 'murder', 'shoot', 'stab', 'explosive'
        ],
        'drugs': [
            'drug', 'cocaine', 'heroin', 'meth', 'fentanyl', 'pill',
            'dealer', 'supply', 'shipment', 'cartel', 'trafficking'
        ],
        'exploitation': [
            'minor', 'child', 'exploit', 'abuse', 'trafficking',
            'victim', 'force', 'coerce'
        ],
        'cyber_crime': [
            'hack', 'breach', 'malware', 'ransomware', 'phishing',
            'password', 'credential', 'exploit', 'vulnerability', 'botnet'
        ],
        'identity_theft': [
            'identity', 'ssn', 'social security', 'passport', 'license',
            'steal', 'fake', 'forge', 'counterfeit', 'impersonate'
        ]
    }
    
    def __init__(self, n_topics: int = 10, n_words: int = 10):
        """
        Initialize topic modeler.
        
        Args:
            n_topics: Number of topics to extract
            n_words: Number of top words per topic
        """
        self.n_topics = n_topics
        self.n_words = n_words
        self.vectorizer = None
        self.lda_model = None
        self._initialized = False
        
    def initialize(self) -> bool:
        """Initialize the LDA model components."""
        try:
            from sklearn.feature_extraction.text import CountVectorizer
            from sklearn.decomposition import LatentDirichletAllocation
            
            self.vectorizer = CountVectorizer(
                max_df=0.95,
                min_df=2,
                stop_words='english',
                max_features=1000
            )
            
            self.lda_model = LatentDirichletAllocation(
                n_components=self.n_topics,
                random_state=42,
                max_iter=10,
                learning_method='online'
            )
            
            self._initialized = True
            logger.info(f"Topic modeler initialized with {self.n_topics} topics")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize topic modeler: {e}")
            return False
    
    def extract_topics(self, documents: List[str]) -> List[Topic]:
        """
        Extract topics from a collection of documents.
        
        Args:
            documents: List of text documents
            
        Returns:
            List of Topic objects
        """
        if not self._initialized:
            if not self.initialize():
                return []
        
        if not documents or len(documents) < 2:
            logger.warning("Need at least 2 documents for topic modeling")
            return []
            
        try:
            # Vectorize documents
            doc_term_matrix = self.vectorizer.fit_transform(documents)
            
            # Fit LDA model
            self.lda_model.fit(doc_term_matrix)
            
            # Extract topics
            feature_names = self.vectorizer.get_feature_names_out()
            topics = []
            
            for topic_idx, topic in enumerate(self.lda_model.components_):
                top_word_indices = topic.argsort()[:-self.n_words - 1:-1]
                top_words = [feature_names[i] for i in top_word_indices]
                weight = float(topic[top_word_indices].sum() / topic.sum())
                
                # Categorize topic
                category, risk = self._categorize_topic(top_words)
                
                topic_obj = Topic(
                    topic_id=topic_idx,
                    keywords=top_words,
                    weight=weight,
                    category=category,
                    risk_level=risk
                )
                topics.append(topic_obj)
            
            # Sort by risk level
            risk_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            topics.sort(key=lambda t: risk_order.get(t.risk_level, 4))
            
            logger.info(f"Extracted {len(topics)} topics")
            return topics
            
        except Exception as e:
            logger.error(f"Topic extraction failed: {e}")
            return []
    
    def analyze_single_document(self, text: str, all_documents: List[str] = None) -> List[Tuple[Topic, float]]:
        """
        Analyze topics in a single document.
        
        Args:
            text: Document text to analyze
            all_documents: Optional corpus for context (improves accuracy)
            
        Returns:
            List of (Topic, probability) tuples
        """
        if not text or not text.strip():
            return []
            
        # If we have a corpus, use it for better topic modeling
        if all_documents and len(all_documents) >= 2:
            topics = self.extract_topics(all_documents)
            if not topics:
                return []
                
            # Get topic distribution for this document
            doc_vector = self.vectorizer.transform([text])
            topic_dist = self.lda_model.transform(doc_vector)[0]
            
            return [(topics[i], float(prob)) for i, prob in enumerate(topic_dist) if prob > 0.1]
        
        # Simple keyword-based analysis for single document
        return self._simple_topic_analysis(text)
    
    def _simple_topic_analysis(self, text: str) -> List[Tuple[Topic, float]]:
        """Simple keyword-based topic detection for single documents."""
        text_lower = text.lower()
        results = []
        
        for category, keywords in self.SUSPICIOUS_CATEGORIES.items():
            matches = sum(1 for kw in keywords if kw in text_lower)
            if matches > 0:
                score = min(1.0, matches / 5)  # Normalize score
                topic = Topic(
                    topic_id=-1,
                    keywords=[kw for kw in keywords if kw in text_lower][:5],
                    weight=score,
                    category=category,
                    risk_level=self._get_category_risk(category)
                )
                results.append((topic, score))
        
        return sorted(results, key=lambda x: x[1], reverse=True)
    
    def _categorize_topic(self, keywords: List[str]) -> Tuple[str, str]:
        """Categorize a topic based on its keywords."""
        keywords_lower = [kw.lower() for kw in keywords]
        
        best_category = 'general'
        best_match_count = 0
        
        for category, category_keywords in self.SUSPICIOUS_CATEGORIES.items():
            match_count = sum(1 for kw in keywords_lower if kw in category_keywords)
            if match_count > best_match_count:
                best_match_count = match_count
                best_category = category
        
        risk = self._get_category_risk(best_category) if best_match_count >= 2 else 'low'
        return best_category, risk
    
    def _get_category_risk(self, category: str) -> str:
        """Get risk level for a category."""
        high_risk = {'violence', 'exploitation', 'drugs'}
        medium_risk = {'financial_fraud', 'cyber_crime', 'identity_theft'}
        
        if category in high_risk:
            return 'high'
        elif category in medium_risk:
            return 'medium'
        return 'low'
