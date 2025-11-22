#!/usr/bin/env python3
"""
models.py - Data models for analysis results.
"""

from dataclasses import dataclass
from typing import List, Dict, Any


@dataclass
class AnalysisResult:
    """Structured analysis result with type safety."""

    jailbreak: bool
    prompt_injection: bool
    harmful_content: bool
    confidence: float
    reasoning: str
    explanation: str
    content_flags: List[str]
    attack_types: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "jailbreak": self.jailbreak,
            "prompt_injection": self.prompt_injection,
            "harmful_content": self.harmful_content,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "explanation": self.explanation,
            "content_flags": self.content_flags,
            "attack_types": self.attack_types,
        }
