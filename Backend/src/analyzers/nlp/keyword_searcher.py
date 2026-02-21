"""
Keyword Searcher Module
Searches for sensitive/criminal keywords with fuzzy matching.
"""

import logging
import re
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass

logger = logging.getLogger("SENTINEL_KEYWORD")


@dataclass
class KeywordMatch:
    """Represents a keyword match in text."""
    keyword: str
    matched_text: str
    category: str
    start: int
    end: int
    context: str
    risk_level: str
    confidence: float


class KeywordSearcher:
    """
    Keyword search for sensitive/criminal content.
    Supports exact and fuzzy matching with context extraction.
    """
    
    # Predefined keyword categories for forensic analysis
    KEYWORD_CATEGORIES = {
        'financial_fraud': {
            'risk': 'high',
            'keywords': [
                'money laundering', 'wire transfer', 'offshore account', 'tax evasion',
                'embezzlement', 'ponzi scheme', 'pyramid scheme', 'kickback',
                'bribe', 'bribery', 'slush fund', 'shell company', 'fraud',
                'counterfeit', 'forgery', 'insider trading', 'securities fraud'
            ]
        },
        'violence_threats': {
            'risk': 'critical',
            'keywords': [
                'kill', 'murder', 'assassinate', 'bomb', 'explosive',
                'attack', 'terrorist', 'terrorism', 'shoot', 'shooting',
                'threaten', 'death threat', 'hostage', 'kidnap', 'ransom'
            ]
        },
        'drugs_trafficking': {
            'risk': 'high',
            'keywords': [
                'cocaine', 'heroin', 'methamphetamine', 'fentanyl', 'opioid',
                'drug deal', 'trafficking', 'cartel', 'smuggle', 'smuggling',
                'narcotics', 'controlled substance', 'dealer', 'distribution'
            ]
        },
        'weapons': {
            'risk': 'high',
            'keywords': [
                'firearm', 'illegal weapon', 'assault rifle', 'ammunition',
                'silencer', 'suppressor', 'gun running', 'arms dealer',
                'explosive device', 'detonator', 'ied'
            ]
        },
        'exploitation': {
            'risk': 'critical',
            'keywords': [
                'human trafficking', 'sex trafficking', 'child exploitation',
                'child abuse', 'csam', 'minor', 'underage', 'forced labor'
            ]
        },
        'cyber_crime': {
            'risk': 'medium',
            'keywords': [
                'ransomware', 'malware', 'phishing', 'hack', 'hacker',
                'data breach', 'stolen data', 'credentials', 'botnet',
                'ddos', 'exploit', 'zero day', 'dark web', 'tor'
            ]
        },
        'identity_fraud': {
            'risk': 'medium',
            'keywords': [
                'stolen identity', 'fake id', 'forged documents', 'identity theft',
                'social security fraud', 'passport fraud', 'impersonation'
            ]
        },
        'corruption': {
            'risk': 'medium',
            'keywords': [
                'corruption', 'collusion', 'conspiracy', 'cover up', 'coverup',
                'obstruction', 'witness tampering', 'perjury', 'blackmail',
                'extortion', 'coercion'
            ]
        }
    }
    
    def __init__(self, custom_keywords: Dict[str, Dict] = None, enable_fuzzy: bool = True):
        """
        Initialize keyword searcher.
        
        Args:
            custom_keywords: Additional keyword categories to include
            enable_fuzzy: Enable fuzzy matching for variations
        """
        self.keywords = dict(self.KEYWORD_CATEGORIES)
        if custom_keywords:
            self.keywords.update(custom_keywords)
        self.enable_fuzzy = enable_fuzzy
        self._compiled_patterns = {}
        self._build_patterns()
        
    def _build_patterns(self):
        """Pre-compile regex patterns for all keywords."""
        for category, data in self.keywords.items():
            patterns = []
            for keyword in data['keywords']:
                # Create pattern that matches word boundaries
                # Allow for common variations (plurals, verb forms)
                escaped = re.escape(keyword)
                pattern = rf'\b{escaped}(?:s|ed|ing|er|tion)?\b'
                patterns.append(pattern)
            
            # Combine all patterns for this category
            combined = '|'.join(patterns)
            self._compiled_patterns[category] = re.compile(combined, re.IGNORECASE)
    
    def search(self, text: str, context_window: int = 100) -> List[KeywordMatch]:
        """
        Search for keywords in text.
        
        Args:
            text: Text to search
            context_window: Characters of context around each match
            
        Returns:
            List of KeywordMatch objects
        """
        if not text or not text.strip():
            return []
            
        matches = []
        
        for category, pattern in self._compiled_patterns.items():
            risk = self.keywords[category]['risk']
            
            for match in pattern.finditer(text):
                # Extract context
                start = max(0, match.start() - context_window)
                end = min(len(text), match.end() + context_window)
                context = text[start:end]
                
                # Find which keyword matched
                matched_keyword = self._find_matching_keyword(
                    match.group(), 
                    self.keywords[category]['keywords']
                )
                
                keyword_match = KeywordMatch(
                    keyword=matched_keyword,
                    matched_text=match.group(),
                    category=category,
                    start=match.start(),
                    end=match.end(),
                    context=context,
                    risk_level=risk,
                    confidence=0.9 if match.group().lower() == matched_keyword.lower() else 0.7
                )
                matches.append(keyword_match)
        
        # Sort by risk level and position
        risk_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        matches.sort(key=lambda m: (risk_order.get(m.risk_level, 4), m.start))
        
        logger.debug(f"Found {len(matches)} keyword matches")
        return matches
    
    def _find_matching_keyword(self, matched_text: str, keywords: List[str]) -> str:
        """Find which keyword best matches the matched text."""
        matched_lower = matched_text.lower()
        
        for keyword in keywords:
            if keyword.lower() in matched_lower or matched_lower.startswith(keyword.lower()):
                return keyword
        
        return matched_text
    
    def get_summary(self, matches: List[KeywordMatch]) -> Dict[str, any]:
        """
        Get a summary of keyword matches.
        
        Args:
            matches: List of KeywordMatch objects
            
        Returns:
            Summary dictionary with counts and risk assessment
        """
        if not matches:
            return {'total': 0, 'by_category': {}, 'by_risk': {}, 'overall_risk': 'low'}
        
        by_category = {}
        by_risk = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for match in matches:
            by_category[match.category] = by_category.get(match.category, 0) + 1
            by_risk[match.risk_level] = by_risk.get(match.risk_level, 0) + 1
        
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
            'total': len(matches),
            'by_category': by_category,
            'by_risk': by_risk,
            'overall_risk': overall_risk
        }
    
    def add_keywords(self, category: str, keywords: List[str], risk: str = 'medium'):
        """
        Add custom keywords to a category.
        
        Args:
            category: Category name
            keywords: List of keywords to add
            risk: Risk level for these keywords
        """
        if category not in self.keywords:
            self.keywords[category] = {'risk': risk, 'keywords': []}
        
        self.keywords[category]['keywords'].extend(keywords)
        self._build_patterns()  # Rebuild patterns
        logger.info(f"Added {len(keywords)} keywords to category '{category}'")
