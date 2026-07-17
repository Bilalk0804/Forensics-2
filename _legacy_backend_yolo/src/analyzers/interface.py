"""
Analyzer Interface Module
Abstract base class defining the contract for all analyzer implementations.
"""

from abc import ABC, abstractmethod


class AnalyzerInterface(ABC):
    """Abstract base class for all analyzers."""

    @abstractmethod
    def analyze(self, data):
        """
        Perform analysis on the given data.
        
        Args:
            data: Input data to analyze
            
        Returns:
            Analysis results
        """
        pass

    @abstractmethod
    def validate(self):
        """Validate analyzer configuration and dependencies."""
        pass
