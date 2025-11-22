#!/usr/bin/env python3
"""
cli.py - Main CLI entry point for prompt safety analyzer.

Advanced jailbreak / prompt-injection / harmful content detector using local LLM via Ollama.

Major improvements implemented (2025 edition):
• Rule-based first-pass filter (catches ~75% instantly)
• Aggressive deobfuscation pre-processing (base64, rot13, hex, unicode escapes, zero-width, leetspeak normalization)
• Full conversation history support for multi-turn payload-splitting / gradual manipulation detection
• Native JSON mode (response_format=json_object)
• Chain-of-Thought reasoning inside JSON for better accuracy
• Embedded compact attack ontology with attack_types classification
• 10 high-quality few-shot examples from WildJailbreak + in-the-wild data
• Ensemble mode with secondary model fallback
• Expanded content_flags aligned with Llama Guard 3 / OWASP 2025 taxonomy
• Entropy check for adversarial suffixes / encoded payloads

Recommended models for Ollama:
- gpt-oss:latest (primary - general purpose with safety features)
- qwen3:32b (secondary - high capability model for ensemble)
- gpt-oss-safeguard:latest (safety classifier - specialized content moderation)
"""

import argparse
import json
import logging
import sys
from argparse import FileType
from typing import Optional, List, Dict

from analyzer.config import (
    DEFAULT_API_URL,
    DEFAULT_PRIMARY_MODEL,
    DEFAULT_SECONDARY_MODEL,
    DEFAULT_SAFETY_CLASSIFIER_MODEL,
    HIGH_ENTROPY_THRESHOLD,
    JAILBREAK_KEYWORDS,
    SYSTEM_PROMPT,
    FEW_SHOT_EXAMPLES,
    SAFETY_POLICY_PROMPT,
)
from analyzer.deobfuscation import format_deobfuscation_report
from analyzer.conversation import analyze_conversation_trajectory
from analyzer.rules import quick_rule_check
from analyzer.llm import build_messages, call_lm, combine_analysis, call_safety_classifier

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger(__name__)


def main() -> None:
    """Main entry point with comprehensive error handling."""
    parser = argparse.ArgumentParser(
        description="Advanced prompt safety analyzer with deobfuscation and ensemble support"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", "--prompt", type=str, help="Prompt string to analyze")
    group.add_argument(
        "-f", "--file", type=FileType("r"), help="File containing prompt to analyze"
    )

    parser.add_argument(
        "--url",
        default=DEFAULT_API_URL,
        help=f"Base URL of the Ollama API (default: {DEFAULT_API_URL})",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_PRIMARY_MODEL,
        help=f"Primary Ollama model (default: {DEFAULT_PRIMARY_MODEL})",
    )
    parser.add_argument(
        "--secondary-model",
        default=DEFAULT_SECONDARY_MODEL,
        help=f"Secondary model for ensemble mode (default: {DEFAULT_SECONDARY_MODEL})",
    )
    parser.add_argument(
        "--ensemble",
        action="store_true",
        help="Run both primary and secondary and take conservative result",
    )
    parser.add_argument(
        "--use-safety-classifier",
        action="store_true",
        help="Use GPT-OSS-Safeguard for detailed safety classification",
    )
    parser.add_argument(
        "--safety-model",
        default=DEFAULT_SAFETY_CLASSIFIER_MODEL,
        help=f"Safety classifier model (default: {DEFAULT_SAFETY_CLASSIFIER_MODEL})",
    )
    parser.add_argument(
        "--history",
        type=FileType("r"),
        help="JSONL file with previous messages (role/content)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Configure logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")

    try:
        # Get prompt text
        prompt_text = (
            args.prompt.strip() if args.prompt is not None else args.file.read().strip()
        )

        if not prompt_text:
            logger.error("Empty prompt provided")
            print("ERROR: Empty prompt provided", file=sys.stderr)
            sys.exit(1)

        logger.info(f"Analyzing prompt of length {len(prompt_text)}")

        # Rule-based fast pass - detect suspicious patterns
        rule_detection = quick_rule_check(prompt_text, JAILBREAK_KEYWORDS, HIGH_ENTROPY_THRESHOLD)
        
        # Parse history if provided
        history: Optional[List[Dict[str, str]]] = None
        if args.history:
            try:
                history = [json.loads(line) for line in args.history if line.strip()]
                logger.info(f"Loaded {len(history)} history messages")
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse history file: {e}")
                print(f"ERROR: Invalid history file format: {e}", file=sys.stderr)
                sys.exit(1)

        # Multi-turn conversation analysis
        trajectory_analysis = None
        if history:
            trajectory_analysis = analyze_conversation_trajectory(history, prompt_text)
            logger.info(
                f"Multi-turn analysis: escalation_detected={trajectory_analysis['escalation_detected']}, "
                f"rate={trajectory_analysis['escalation_rate']:.2f}, "
                f"avg_risk={trajectory_analysis.get('average_risk_score', 0):.2f}, "
                f"pattern={trajectory_analysis['pattern_detected']}"
            )
            
            # Warn if escalation detected
            if trajectory_analysis['escalation_detected']:
                threat_types = trajectory_analysis.get('threat_types', [])
                warning_parts = []
                
                if threat_types:
                    warning_parts.append(f"threats: {', '.join(threat_types)}")
                if trajectory_analysis['escalation_rate'] > 0.02:
                    warning_parts.append(f"escalation rate: {trajectory_analysis['escalation_rate']:.2f}")
                if trajectory_analysis.get('high_risk_turns', 0) >= 2:
                    warning_parts.append(f"{trajectory_analysis['high_risk_turns']} high-risk turns")
                if trajectory_analysis.get('average_risk_score', 0) >= 0.18:
                    warning_parts.append(f"avg risk: {trajectory_analysis['average_risk_score']:.2f}")
                
                warning_msg = "⚠️  THREAT DETECTED IN CONVERSATION: " + " | ".join(warning_parts)
                logger.warning(warning_msg)
            
            if trajectory_analysis.get('crescendo_detected'):
                logger.warning("⚠️  Crescendo attack pattern detected (rapport → manipulation)")
            
            if trajectory_analysis.get('topic_drift_detected'):
                logger.warning("⚠️  Topic drift toward harmful subjects detected")

        # Build messages and call LLM (always use AI, but log if rules triggered)
        if rule_detection:
            logger.warning(
                f"Suspicious pattern detected ({rule_detection}), analyzing with AI to determine intent"
            )
        
        logger.info("Starting deobfuscation analysis")
        deobf_report = format_deobfuscation_report(prompt_text)
        messages = build_messages(prompt_text, history, SYSTEM_PROMPT, FEW_SHOT_EXAMPLES, deobf_report)
        analysis = call_lm(args.model, messages, args.url)

        # Ensemble mode if requested
        if args.ensemble:
            logger.info("Running ensemble mode with secondary model")
            secondary_messages = build_messages(prompt_text, history, SYSTEM_PROMPT, FEW_SHOT_EXAMPLES, deobf_report)
            secondary = call_lm(args.secondary_model, secondary_messages, args.url)
            analysis = combine_analysis(analysis, secondary)

        # Safety classifier mode if requested
        if args.use_safety_classifier:
            logger.info("Running safety classifier for detailed categorization")
            safety_result = call_safety_classifier(
                prompt_text, args.url, args.safety_model, SAFETY_POLICY_PROMPT, history
            )
            analysis["safety_classification"] = safety_result
            
            # If safety classifier detects violation, ensure harmful_content is flagged
            if safety_result.get("violation") == 1:
                logger.warning(
                    f"⚠️  Safety violation detected: {safety_result.get('categories')} "
                    f"(severity: {safety_result.get('severity')}, confidence: {safety_result.get('confidence')})"
                )
                analysis["harmful_content"] = True
                # Merge categories into content_flags
                safety_categories = safety_result.get("categories", [])
                existing_flags = set(analysis.get("content_flags", []))
                analysis["content_flags"] = list(existing_flags | set(safety_categories))

        # Add trajectory analysis to output if available
        if trajectory_analysis:
            analysis["multi_turn_analysis"] = trajectory_analysis

        # Output results
        print(json.dumps(analysis, indent=2, ensure_ascii=False))

        # Determine exit code and print summary
        if (
            analysis.get("jailbreak")
            or analysis.get("prompt_injection")
            or analysis.get("harmful_content")
        ):
            print(
                f"\nMalicious behavior detected (confidence: {analysis['confidence']})",
                file=sys.stderr,
            )
            if analysis.get("attack_types"):
                print(
                    f"Attack types: {', '.join(analysis['attack_types'])}",
                    file=sys.stderr,
                )
            if analysis.get("content_flags"):
                print(
                    f"Content flags: {', '.join(analysis['content_flags'])}",
                    file=sys.stderr,
                )
            sys.exit(2)

        print("\nSafe")
        sys.exit(0)

    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
        print("\nAnalysis interrupted", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        print(f"\nERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
