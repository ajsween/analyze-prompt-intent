#!/usr/bin/env python3
"""
llm.py - LLM interaction and analysis functions.
"""

import json
import logging
import re
import sys
from typing import Dict, List, Optional, Any

from openai import OpenAI

logger = logging.getLogger(__name__)


def build_messages(
    prompt: str,
    history: Optional[List[Dict[str, str]]],
    system_prompt: str,
    few_shot_examples: List[Dict[str, str]],
    deobfuscation_report: str
) -> List[Dict[str, str]]:
    """Build message list for LLM with deobfuscated prompt and conversation history."""
    logger.debug(f"Building messages for prompt of length {len(prompt)}")
    user_content = f"Analyze the following user input (including any decoded versions):\n\n{deobfuscation_report}"

    messages: List[Dict[str, str]] = [{"role": "system", "content": system_prompt}]

    if history:
        logger.debug(f"Adding {len(history)} history messages")
        messages.extend(history)

    messages.extend(few_shot_examples)
    messages.append({"role": "user", "content": user_content})

    return messages


def call_lm(
    model: str, messages: List[Dict[str, str]], url: str, use_json_mode: bool = True
) -> Dict[str, Any]:
    """Call LLM with proper error handling and retry logic."""
    logger.info(f"Calling model {model} at {url}")
    client = OpenAI(base_url=url.rstrip("/"), api_key="not-needed")

    try:
        kwargs: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": 0.0,
        }
        if use_json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        response = client.chat.completions.create(**kwargs)
        reply = response.choices[0].message.content

        if not reply:
            logger.error("Empty response from model")
            raise ValueError("Empty response from model")

        reply = reply.strip()
        logger.debug(f"Received response of length {len(reply)}")
        return json.loads(reply)

    except json.JSONDecodeError as e:
        logger.warning(f"JSON decode error: {e}, attempting fallback parsing")
        # fallback parsing if JSON is malformed
        try:
            reply = response.choices[0].message.content
            if not reply:
                raise ValueError("Empty response during fallback")
            reply = reply.strip()
            json_match = re.search(r"\{.*\}", reply, flags=re.DOTALL)
            if json_match:
                return json.loads(json_match.group(0))
        except (json.JSONDecodeError, AttributeError, ValueError) as fallback_err:
            logger.error(f"Fallback parsing also failed: {fallback_err}")

        logger.error("Could not parse JSON from model response")
        sys.exit(1)

    except Exception as e:
        error_msg = str(e)
        # Retry without json_object mode if not supported
        if use_json_mode and "response_format" in error_msg:
            logger.warning("JSON mode not supported, retrying without it")
            return call_lm(model, messages, url, use_json_mode=False)

        logger.error(f"LM request failed: {e}")
        sys.exit(1)


def combine_analysis(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """Combine two analysis results conservatively (union of threats)."""
    logger.info("Combining ensemble results")
    combined: Dict[str, Any] = {}
    combined["jailbreak"] = a["jailbreak"] or b["jailbreak"]
    combined["prompt_injection"] = a["prompt_injection"] or b["prompt_injection"]
    combined["harmful_content"] = a["harmful_content"] or b["harmful_content"]
    combined["confidence"] = max(a["confidence"], b["confidence"])
    combined["reasoning"] = (
        f"Primary reasoning:\n{a['reasoning']}\n\nSecondary reasoning:\n{b['reasoning']}"
    )
    combined["explanation"] = (
        a["explanation"] if a["confidence"] >= b["confidence"] else b["explanation"]
    )
    combined["content_flags"] = list(
        set(a.get("content_flags", []) + b.get("content_flags", []))
    )
    combined["attack_types"] = list(
        set(a.get("attack_types", []) + b.get("attack_types", []))
    )
    return combined


def call_safety_classifier(
    prompt: str,
    url: str,
    model: str,
    safety_policy_prompt: str,
    history: Optional[List[Dict[str, str]]] = None
) -> Dict[str, Any]:
    """
    Call GPT-OSS-Safeguard safety classifier using Harmony response format.
    
    Args:
        prompt: The user input to classify
        url: Base URL of the Ollama API
        model: Safety classifier model name
        safety_policy_prompt: Safety policy template
        history: Optional conversation history for context
    
    Returns:
        Dictionary with safety classification results:
        {
            "violation": 0 or 1,
            "categories": ["category1", "category2"],
            "severity": "low" | "medium" | "high" | "critical",
            "confidence": "low" | "medium" | "high",
            "rationale": "Brief explanation"
        }
    """
    logger.info(f"Calling safety classifier {model}")
    client = OpenAI(base_url=url.rstrip("/"), api_key="not-needed")
    
    # Build full context including history
    if history:
        # Extract user turns from history for context
        user_turns = [msg["content"] for msg in history if msg["role"] == "user"]
        context = "Conversation history:\n" + "\n".join(f"User: {turn}" for turn in user_turns)
        context += f"\n\nCurrent user message: {prompt}"
    else:
        context = prompt
    
    # Build policy prompt with full context
    policy_content = safety_policy_prompt.replace("{INPUT}", context)
    
    messages = [
        {"role": "system", "content": policy_content}
    ]
    
    try:
        # Call with JSON mode for structured output
        response = client.chat.completions.create(
            model=model,
            messages=messages,
            temperature=0.0,
            response_format={"type": "json_object"}
        )
        
        reply = response.choices[0].message.content
        if not reply:
            logger.error("Empty response from safety classifier")
            raise ValueError("Empty response from safety classifier")
        
        result = json.loads(reply.strip())
        logger.debug(f"Safety classification: violation={result.get('violation')}, categories={result.get('categories')}")
        return result
        
    except json.JSONDecodeError as e:
        logger.warning(f"JSON decode error from safety classifier: {e}")
        # Fallback: try to extract JSON from response
        try:
            reply = response.choices[0].message.content
            if reply:
                json_match = re.search(r"\{.*\}", reply, flags=re.DOTALL)
                if json_match:
                    return json.loads(json_match.group(0))
        except Exception as fallback_err:
            logger.error(f"Fallback parsing failed: {fallback_err}")
        
        # Return safe classification on error
        logger.error("Could not parse safety classifier response, defaulting to safe")
        return {
            "violation": 0,
            "categories": [],
            "severity": "low",
            "confidence": "low",
            "rationale": "Error during classification"
        }
    
    except Exception as e:
        logger.error(f"Safety classifier request failed: {e}")
        # Return safe classification on error to avoid false positives
        return {
            "violation": 0,
            "categories": [],
            "severity": "low",
            "confidence": "low",
            "rationale": f"Classification error: {str(e)}"
        }
