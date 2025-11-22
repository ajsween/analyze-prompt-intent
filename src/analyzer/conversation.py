#!/usr/bin/env python3
"""
conversation_analysis.py - Multi-turn conversation trajectory analysis

Detects progressive jailbreak attacks across conversation turns:
- Linear jailbreaking (gradual escalation)
- Crescendo attacks (rapport building → manipulation)
- Topic drift toward harmful content
- Sentiment/tone changes

Based on 2024-2025 research:
- "Reasoning-Augmented Conversation for Multi-Turn Jailbreak Attacks" (EMNLP 2025)
- "Multi-Turn Jailbreaks Are Simpler Than They Seem" (arXiv 2025)
"""

import logging
import re
from typing import Dict, List, Optional

from analyzer.config import JAILBREAK_KEYWORDS

logger = logging.getLogger(__name__)


def analyze_conversation_trajectory(
    history: List[Dict[str, str]], current_prompt: str
) -> Dict[str, any]:
    """
    Analyze conversation trajectory for multi-turn attack patterns.

    Args:
        history: List of previous conversation turns (role + content)
        current_prompt: The current prompt being analyzed

    Returns:
        Dict with escalation metrics and detection flags
    """
    if not history:
        return {
            "escalation_detected": False,
            "escalation_rate": 0.0,
            "turns_analyzed": 0,
            "risk_progression": [],
            "pattern_detected": None,
        }

    # Extract user turns only
    user_turns = [
        msg["content"] for msg in history if msg.get("role") == "user"
    ] + [current_prompt]

    if len(user_turns) < 2:
        return {
            "escalation_detected": False,
            "escalation_rate": 0.0,
            "turns_analyzed": len(user_turns),
            "risk_progression": [],
            "pattern_detected": None,
        }

    # Calculate risk score for each turn
    risk_scores = [calculate_turn_risk(turn) for turn in user_turns]

    # Detect escalation pattern
    escalation_detected, pattern = detect_escalation_pattern(risk_scores)

    # Calculate escalation rate (slope of risk increase)
    escalation_rate = calculate_escalation_rate(risk_scores)

    # Check for crescendo pattern (rapport building → manipulation)
    crescendo_detected = detect_crescendo_pattern(user_turns, risk_scores)

    # Check for topic drift
    drift_detected = detect_topic_drift(user_turns)

    # Check for sustained high risk (multiple turns above threshold)
    high_risk_threshold = 0.25
    high_risk_turns = sum(1 for score in risk_scores if score >= high_risk_threshold)
    sustained_high_risk = high_risk_turns >= 2  # At least 2 high-risk turns
    
    # Check if any turn had very high risk (>0.4)
    very_high_risk = any(score >= 0.4 for score in risk_scores)
    
    # Calculate average risk across all turns
    avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
    persistent_risk = avg_risk >= 0.18  # Lowered to catch more hostile conversations
    
    # Check for consistently hostile behavior (no benign turns)
    benign_threshold = 0.1
    benign_turns = sum(1 for score in risk_scores if score < benign_threshold)
    consistently_hostile = benign_turns == 0 and len(risk_scores) >= 3
    
    # Check for repeated harmful requests (same type of malicious content)
    repeated_malicious = high_risk_turns >= 3 and len(risk_scores) >= 4
    
    # Detect jailbreak attempts in history
    jailbreak_keywords_in_history = any(
        any(kw in turn.lower() for kw in ["ignore", "disregard", "forget", "override", "bypass"])
        for turn in user_turns
    )

    # Flag as escalating/threatening if:
    # 1. Positive escalation rate (actually increasing)
    # 2. Pattern detected with sustained elevation
    # 3. Multiple high-risk turns (sustained hostility)
    # 4. Any very high risk turn (critical threat)
    # 5. Persistently elevated average risk
    # 6. Consistently hostile throughout (no benign turns)
    # 7. Repeated malicious requests (3+ harmful turns)
    # 8. Jailbreak attempt detected in conversation
    is_escalating = (
        (escalation_rate > 0.02) 
        or escalation_detected 
        or crescendo_detected
        or sustained_high_risk
        or very_high_risk
        or persistent_risk
        or consistently_hostile
        or repeated_malicious
        or jailbreak_keywords_in_history
    )
    
    # Determine threat type for better reporting
    threat_types = []
    if escalation_detected:
        threat_types.append(f"{pattern}_escalation")
    if crescendo_detected:
        threat_types.append("crescendo_attack")
    if consistently_hostile:
        threat_types.append("persistent_hostility")
    if repeated_malicious:
        threat_types.append("repeated_malicious_requests")
    if jailbreak_keywords_in_history:
        threat_types.append("jailbreak_attempt")
    if drift_detected:
        threat_types.append("topic_drift")

    logger.info(
        f"Multi-turn analysis: {len(user_turns)} turns, "
        f"escalation_rate={escalation_rate:.2f}, avg_risk={avg_risk:.2f}, "
        f"high_risk_turns={high_risk_turns}, threats={threat_types}, "
        f"escalating={is_escalating}"
    )

    return {
        "escalation_detected": is_escalating,
        "escalation_rate": escalation_rate,
        "turns_analyzed": len(user_turns),
        "risk_progression": risk_scores,
        "pattern_detected": pattern if escalation_detected else None,
        "threat_types": threat_types,
        "crescendo_detected": crescendo_detected,
        "topic_drift_detected": drift_detected,
        "final_risk_score": risk_scores[-1],
        "initial_risk_score": risk_scores[0],
        "average_risk_score": avg_risk,
        "high_risk_turns": high_risk_turns,
        "sustained_high_risk": sustained_high_risk,
        "consistently_hostile": consistently_hostile,
        "repeated_malicious": repeated_malicious,
        "jailbreak_in_history": jailbreak_keywords_in_history,
    }


def calculate_turn_risk(text: str) -> float:
    """
    Calculate risk score for a single turn (0.0 to 1.0).
    
    Based on Microsoft Prompt Shields taxonomy and 2024-2025 jailbreak research.

    Factors:
    - System rule manipulation attempts
    - Role-play and persona replacement
    - Obfuscation and encoding patterns
    - Harmful instruction requests
    - Multi-turn attack indicators
    """
    risk = 0.0
    lower_text = text.lower()

    # Check for jailbreak keywords (0.0 to 0.5)
    keyword_matches = sum(1 for kw in JAILBREAK_KEYWORDS if kw in lower_text)
    risk += min(keyword_matches * 0.15, 0.5)

    # Category 1: System Rule Manipulation (0.0 to 0.45)
    # Microsoft Prompt Shields: "Attempt to change system rules"
    system_manipulation_patterns = [
        r"\b(?:ignore|disregard|forget|bypass|override|disable)\s+(?:all|any|previous|the|your)?\s*(?:instructions?|rules?|guidelines?|constraints?|limitations?|restrictions?|policies|safeguards?|filters?)\b",
        r"\b(?:you are now|from now on|starting now|new instructions?|updated instructions?)\b",
        r"\bnew\s+(?:role|persona|character|system|rules?|mode)\b",
        r"\b(?:unrestricted|unfiltered|uncensored|no limits?|no rules?|no restrictions?)\b",
        r"\bact as (?:if|though)?\s*(?:you have|there are)?\s*no\s+(?:rules?|restrictions?|limitations?)\b",
        r"\b(?:dan|developer mode|jailbreak|admin mode|god mode|root access)\b",
    ]
    system_matches = sum(
        1 for pattern in system_manipulation_patterns if re.search(pattern, lower_text, re.IGNORECASE)
    )
    risk += min(system_matches * 0.15, 0.45)

    # Category 2: Role-Play and Persona Replacement (0.0 to 0.35)
    # Microsoft: "Role-Play" attacks that replace system persona
    roleplay_patterns = [
        r"\b(?:pretend|act as|roleplay|imagine|you are now|you will be|become)\s+(?:a|an|that)?\s*(?:character|person|ai|assistant|chatbot|entity)\b",
        r"\blet'?s play\s+(?:a game|pretend)\b",
        r"\bin (?:a|the|this)?\s*(?:fictional|hypothetical|alternate|parallel)\s+(?:world|universe|reality|scenario|story)\b",
        r"\bfor\s+(?:a|the|this)?\s*(?:movie|story|novel|book|script|game|creative writing|fiction)\b",
        r"\byou\s+(?:have|possess)\s+(?:emotions?|feelings?|thoughts?|opinions?|desires?)\b",
        r"\bas\s+(?:a character|an entity|someone)\s+(?:named|called|known as)\b",
    ]
    roleplay_matches = sum(
        1 for pattern in roleplay_patterns if re.search(pattern, lower_text, re.IGNORECASE)
    )
    risk += min(roleplay_matches * 0.12, 0.35)

    # Category 3: Encoding/Obfuscation Indicators (0.0 to 0.30)
    # Microsoft: "Encoding Attacks" - character transformation, ciphers
    encoding_patterns = [
        r"\b(?:encode|decode|encrypt|decrypt|cipher|rot13|base64|hex|unicode|ascii)\b",
        r"\bspeak in\s+(?:code|cipher|encoded|binary|hex)\b",
        r"\burl encoding|character transformation|leetspeak|substitution\b",
        r"\btranslate to\s+(?:binary|hex|base64|rot13)\b",
        r"(?:[a-zA-Z0-9+/]{20,}={0,2})",  # Potential base64
        r"(?:\\u[0-9a-fA-F]{4}){3,}",  # Unicode escape sequences
    ]
    encoding_matches = sum(
        1 for pattern in encoding_patterns if re.search(pattern, lower_text, re.IGNORECASE)
    )
    risk += min(encoding_matches * 0.15, 0.30)

    # Category 4: Multi-Turn Attack Indicators (0.0 to 0.25)
    # Research: Crescendo, payload splitting, gradual escalation
    multiturn_patterns = [
        r"\b(?:continue|keep going|next step|step \d+|part \d+|move on|proceed)\b",
        r"\b(?:now|then|after that|following that|subsequently)\s+(?:can you|could you|please|tell me)\b",
        r"\b(?:building on|based on)\s+(?:that|this|what you said|your previous)\b",
        r"\b(?:expand|elaborate|go deeper|more detail|specifically)\s+on\b",
    ]
    multiturn_matches = sum(
        1 for pattern in multiturn_patterns if re.search(pattern, lower_text, re.IGNORECASE)
    )
    risk += min(multiturn_matches * 0.08, 0.25)

    # Category 5: Harmful Instruction Requests (0.0 to 0.40)
    # OWASP LLM Top 10: Harmful content generation requests
    harmful_instruction_patterns = [
        r"\b(?:how to|how do i|how can i|steps? to|guide (?:to|for|on)|tutorial (?:on|for)|instructions? (?:for|on|to))\s+(?:make|create|build|develop|write|generate|produce)\b",
        r"\b(?:step[- ]by[- ]step|detailed instructions?|complete guide|full tutorial)\b",
        r"\b(?:teach|show|tell|explain|describe|provide|give)\s+(?:me|us)\s+(?:how to|the (?:process|method|way|steps?))\b",
        r"\b(?:write|generate|create|make|produce)\s+(?:a|an)?\s*(?:script|code|program|malware|virus|exploit|payload)\b",
        r"\b(?:methods?|techniques?|ways?|approaches?)\s+(?:to|for)\s+(?:hack|exploit|bypass|circumvent|break|attack|penetrate)\b",
        r"\b(?:vulnerabilities|exploits?|weaknesses|flaws)\s+(?:in|for|to)\b",
        r"\bweapon|explosive|bomb|poison|drug synthesis|phishing|scam|fraud\b",
    ]
    harmful_matches = sum(
        1 for pattern in harmful_instruction_patterns if re.search(pattern, lower_text, re.IGNORECASE)
    )
    risk += min(harmful_matches * 0.13, 0.40)

    # Category 6: Context Manipulation/Conversation Mockup (0.0 to 0.20)
    # Microsoft: "Embedding a conversation mockup to confuse the model"
    context_manipulation = [
        r"(?:user|assistant|system|human|ai):\s*[^\n]{10,}",  # Fake conversation turns
        r"\[(?:user|assistant|system)\]",  # Bracketed role indicators
        r"(?:previous (?:conversation|chat|dialogue|exchange)|chat history|conversation log)\b",
    ]
    context_matches = sum(
        1 for pattern in context_manipulation if re.search(pattern, lower_text, re.IGNORECASE)
    )
    risk += min(context_matches * 0.10, 0.20)

    return min(risk, 1.0)


def detect_escalation_pattern(risk_scores: List[float]) -> tuple[bool, Optional[str]]:
    """
    Detect if risk scores show escalation pattern.

    Patterns:
    - Linear: steady increase over turns
    - Exponential: accelerating increase
    - Step: sudden upward jumps with sustained elevated risk
    
    Returns (False, None) if conversation is de-escalating or stable.
    """
    if len(risk_scores) < 3:
        return False, None

    # Check overall trend - if final risk is lower than initial, no escalation
    if risk_scores[-1] <= risk_scores[0]:
        return False, None

    # Calculate differences between consecutive scores
    diffs = [risk_scores[i + 1] - risk_scores[i] for i in range(len(risk_scores) - 1)]

    # Linear escalation: mostly positive differences AND increasing trend
    positive_diffs = sum(1 for d in diffs if d > 0.03)  # Lowered from 0.05
    if positive_diffs >= len(diffs) * 0.6:  # 60% of turns show increase
        return True, "linear"

    # Step pattern: large upward jump(s) with sustained or increasing risk afterward
    for i, d in enumerate(diffs):
        if d > 0.2:  # Large upward jump detected
            # Check if risk stays elevated (doesn't drop back down significantly)
            post_jump_scores = risk_scores[i + 1:]
            if len(post_jump_scores) > 1:
                # Risk must stay above or near the jump level
                jump_level = risk_scores[i + 1]
                sustained = all(score >= jump_level * 0.7 for score in post_jump_scores)
                if sustained:
                    return True, "step"
            elif post_jump_scores:
                # Single turn after jump - just check it's elevated
                if post_jump_scores[0] >= risk_scores[i] + 0.15:
                    return True, "step"

    # Exponential: differences themselves increasing (accelerating escalation)
    if len(diffs) >= 3:
        diff_diffs = [diffs[i + 1] - diffs[i] for i in range(len(diffs) - 1)]
        increasing_acceleration = sum(1 for dd in diff_diffs if dd > 0)
        if increasing_acceleration >= len(diff_diffs) * 0.5:  # 50% show acceleration
            return True, "exponential"

    return False, None


def calculate_escalation_rate(risk_scores: List[float]) -> float:
    """
    Calculate escalation rate (slope of risk increase).

    Returns: Average increase per turn (0.0 to 1.0)
    """
    if len(risk_scores) < 2:
        return 0.0

    # Simple linear regression slope
    n = len(risk_scores)
    x_mean = (n - 1) / 2  # 0, 1, 2, ... n-1
    y_mean = sum(risk_scores) / n

    numerator = sum((i - x_mean) * (risk_scores[i] - y_mean) for i in range(n))
    denominator = sum((i - x_mean) ** 2 for i in range(n))

    if denominator == 0:
        return 0.0

    slope = numerator / denominator
    return max(0.0, slope)  # Return 0 if negative (de-escalation)


def detect_crescendo_pattern(
    user_turns: List[str], risk_scores: List[float]
) -> bool:
    """
    Detect crescendo attack pattern:
    - Early turns: benign rapport-building
    - Later turns: escalation to harmful requests

    Pattern: Low risk → ... → Low risk → High risk
    """
    if len(user_turns) < 3:
        return False

    # Check if early turns are benign (rapport building)
    early_turns = len(user_turns) // 2
    early_avg = sum(risk_scores[:early_turns]) / early_turns

    # Check if final turn is high risk
    final_risk = risk_scores[-1]

    # Crescendo: early turns benign (<0.4), final turn risky (>0.4)
    if early_avg < 0.4 and final_risk > 0.4:  # Lowered thresholds from 0.3 and 0.5
        # Also check for sudden jump
        if len(risk_scores) >= 2:
            jump = final_risk - risk_scores[-2]
            if jump > 0.2:  # Lowered from 0.3
                logger.warning(
                    f"Crescendo pattern detected: early_avg={early_avg:.2f}, "
                    f"final={final_risk:.2f}, jump={jump:.2f}"
                )
                return True

    return False


def detect_topic_drift(user_turns: List[str]) -> bool:
    """
    Detect topic drift toward harmful subjects.

    Simple heuristic: check if conversation starts benign and drifts toward
    jailbreak-related topics.
    """
    if len(user_turns) < 3:
        return False

    # Count jailbreak keywords in early vs late turns
    mid_point = len(user_turns) // 2
    early_turns = user_turns[:mid_point]
    late_turns = user_turns[mid_point:]

    early_keyword_count = sum(
        sum(1 for kw in JAILBREAK_KEYWORDS if kw in turn.lower())
        for turn in early_turns
    )

    late_keyword_count = sum(
        sum(1 for kw in JAILBREAK_KEYWORDS if kw in turn.lower())
        for turn in late_turns
    )

    # Topic drift: keywords appear significantly more in later turns
    if early_keyword_count == 0 and late_keyword_count >= 2:
        logger.warning(
            f"Topic drift detected: early_keywords=0, late_keywords={late_keyword_count}"
        )
        return True

    return False
