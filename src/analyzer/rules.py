#!/usr/bin/env python3
"""
rules.py - Rule-based detection for quick pattern matching.
"""

import logging
import math
from collections import Counter
from typing import Optional

logger = logging.getLogger(__name__)


def quick_rule_check(prompt: str, jailbreak_keywords: list, high_entropy_threshold: float) -> Optional[str]:
    """
    Quick rule-based check for suspicious patterns.
    
    Args:
        prompt: The text to analyze
        jailbreak_keywords: List of known jailbreak phrases
        high_entropy_threshold: Threshold for entropy detection
    
    Returns:
        None if no suspicious patterns detected
        "keyword_match" if jailbreak keywords detected
        "high_entropy" if high entropy detected
    """
    lower = prompt.lower()
    if any(phrase in lower for phrase in jailbreak_keywords):
        matched_phrases = [p for p in jailbreak_keywords if p in lower][:3]
        logger.info(
            f"Rule-based trigger: detected jailbreak phrase(s): {matched_phrases}"
        )
        return "keyword_match"

    # High entropy = likely adversarial suffix or encoded payload
    if len(prompt) > 80:
        entropy = calculate_entropy(prompt)
        if entropy > high_entropy_threshold:
            logger.info(
                f"High Shannon entropy ({entropy:.2f}) detected - potential adversarial suffix"
            )
            return "high_entropy"

    return None


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of text."""
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy
