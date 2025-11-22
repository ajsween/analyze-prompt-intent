#!/usr/bin/env python3
"""
obfuscation.py - Advanced obfuscation detection and decoding module

Supports multiple encoding/obfuscation techniques discovered in 2024-2025 research:
- Base64/Base32/Base85 variants
- ROT13/Caesar cipher (all shifts)
- Atbash cipher
- Hex encoding (various formats)
- URL encoding
- Unicode escape sequences
- Unicode homoglyphs and normalization attacks
- Unicode tags (invisible characters)
- Unicode variation selectors (imperceptible jailbreaks 2025)
- Morse code
- Leetspeak (advanced mapping)
- Reverse text
- Mixed case obfuscation
- Typoglycemia (scrambled words)
- Braille unicode encoding
- NATO phonetic alphabet encoding
- Emoji smuggling
"""

import base64
import codecs
import re
import unicodedata
from difflib import SequenceMatcher
from typing import List, Tuple
from urllib.parse import unquote


# Unicode homoglyph mapping (common lookalikes)
HOMOGLYPH_MAP = str.maketrans(
    {
        # Cyrillic to Latin
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "А": "A",
        "В": "B",
        "Е": "E",
        "К": "K",
        "М": "M",
        "Н": "H",
        "О": "O",
        "Р": "P",
        "С": "C",
        "Т": "T",
        "Х": "X",
        # Greek to Latin
        "α": "a",
        "β": "b",
        "γ": "g",
        "δ": "d",
        "ε": "e",
        "ζ": "z",
        "η": "h",
        "θ": "th",
        "ι": "i",
        "κ": "k",
        "λ": "l",
        "μ": "m",
        "ν": "n",
        "ξ": "x",
        "ο": "o",
        "π": "p",
        "ρ": "r",
        "σ": "s",
        "τ": "t",
        "υ": "u",
        "φ": "ph",
        "χ": "ch",
        "ψ": "ps",
        "ω": "o",
    }
)

# Extended leetspeak mapping
LEET_MAP = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "8": "b",
        "@": "a",
        "$": "s",
        "!": "i",
        "|": "l",
        "+": "t",
        "(": "c",
        ")": "c",
        "[": "c",
        "]": "c",
        "{": "c",
        "}": "c",
        "<": "c",
        ">": "c",
    }
)

# Zero-width and invisible Unicode characters
INVISIBLE_CHARS = [
    "\u200b",  # Zero Width Space
    "\u200c",  # Zero Width Non-Joiner
    "\u200d",  # Zero Width Joiner
    "\u2060",  # Word Joiner
    "\u2061",  # Function Application
    "\u2062",  # Invisible Times
    "\u2063",  # Invisible Separator
    "\u2064",  # Invisible Plus
    "\u2066",  # Left-to-Right Isolate
    "\u2067",  # Right-to-Left Isolate
    "\u2068",  # First Strong Isolate
    "\u2069",  # Pop Directional Isolate
    "\ufeff",  # Zero Width No-Break Space (BOM)
    "\u180e",  # Mongolian Vowel Separator
    "\u034f",  # Combining Grapheme Joiner
]

# Unicode tag characters (E0000-E007F range - used for invisible text)
UNICODE_TAG_RANGE = range(0xE0000, 0xE0080)

# Unicode variation selectors (FE00-FE0F and E0100-E01EF) - imperceptible jailbreaks
VARIATION_SELECTORS = list(range(0xFE00, 0xFE10)) + list(range(0xE0100, 0xE01F0))

# NATO Phonetic Alphabet mapping
NATO_PHONETIC = {
    "alfa": "a",
    "alpha": "a",
    "bravo": "b",
    "charlie": "c",
    "delta": "d",
    "echo": "e",
    "foxtrot": "f",
    "golf": "g",
    "hotel": "h",
    "india": "i",
    "juliett": "j",
    "juliet": "j",
    "kilo": "k",
    "lima": "l",
    "mike": "m",
    "november": "n",
    "oscar": "o",
    "papa": "p",
    "quebec": "q",
    "romeo": "r",
    "sierra": "s",
    "tango": "t",
    "uniform": "u",
    "victor": "v",
    "whiskey": "w",
    "whisky": "w",
    "x-ray": "x",
    "xray": "x",
    "yankee": "y",
    "zulu": "z",
}

# Braille Unicode patterns (U+2800 to U+28FF)
# Basic braille letter mapping for English alphabet
BRAILLE_PATTERNS = {
    "⠁": "a",
    "⠃": "b",
    "⠉": "c",
    "⠙": "d",
    "⠑": "e",
    "⠋": "f",
    "⠛": "g",
    "⠓": "h",
    "⠊": "i",
    "⠚": "j",
    "⠅": "k",
    "⠇": "l",
    "⠍": "m",
    "⠝": "n",
    "⠕": "o",
    "⠏": "p",
    "⠟": "q",
    "⠗": "r",
    "⠎": "s",
    "⠞": "t",
    "⠥": "u",
    "⠧": "v",
    "⠺": "w",
    "⠭": "x",
    "⠽": "y",
    "⠵": "z",
    "⠼": "#",  # number sign
    "⠀": " ",  # space
}

# Common jailbreak-related words for fuzzy matching
JAILBREAK_TERMS = [
    "ignore",
    "bypass",
    "system",
    "admin",
    "hack",
    "jailbreak",
    "override",
    "prompt",
    "instructions",
    "rules",
    "constraints",
    "policy",
]


# Morse code mapping
MORSE_CODE = {
    "A": ".-",
    "B": "-...",
    "C": "-.-.",
    "D": "-..",
    "E": ".",
    "F": "..-.",
    "G": "--.",
    "H": "....",
    "I": "..",
    "J": ".---",
    "K": "-.-",
    "L": ".-..",
    "M": "--",
    "N": "-.",
    "O": "---",
    "P": ".--.",
    "Q": "--.-",
    "R": ".-.",
    "S": "...",
    "T": "-",
    "U": "..-",
    "V": "...-",
    "W": ".--",
    "X": "-..-",
    "Y": "-.--",
    "Z": "--..",
    "0": "-----",
    "1": ".----",
    "2": "..---",
    "3": "...--",
    "4": "....-",
    "5": ".....",
    "6": "-....",
    "7": "--...",
    "8": "---..",
    "9": "----.",
    " ": "/",
}
MORSE_DECODE = {v: k for k, v in MORSE_CODE.items()}


def caesar_shift(text: str, shift: int) -> str:
    """Apply Caesar cipher with given shift."""
    result = []
    for char in text:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            shifted = (ord(char) - base + shift) % 26 + base
            result.append(chr(shifted))
        else:
            result.append(char)
    return "".join(result)


def atbash_decode(text: str) -> str:
    """Decode Atbash cipher (reverse alphabet)."""
    result = []
    for char in text:
        if char.isalpha():
            if char.isupper():
                result.append(chr(ord("Z") - (ord(char) - ord("A"))))
            else:
                result.append(chr(ord("z") - (ord(char) - ord("a"))))
        else:
            result.append(char)
    return "".join(result)


def decode_morse(text: str) -> str:
    """Decode Morse code."""
    words = text.split("/")
    decoded_words = []
    for word in words:
        letters = word.strip().split()
        decoded_letters = [
            MORSE_DECODE.get(letter, "?") for letter in letters if letter
        ]
        decoded_words.append("".join(decoded_letters))
    return " ".join(decoded_words)


def decode_braille(text: str) -> Tuple[str, bool]:
    """Decode Braille Unicode characters."""
    decoded = []
    found_braille = False

    for char in text:
        if char in BRAILLE_PATTERNS:
            decoded.append(BRAILLE_PATTERNS[char])
            found_braille = True
        elif "\u2800" <= char <= "\u28ff":  # Braille Patterns Unicode block
            decoded.append("?")
            found_braille = True
        else:
            decoded.append(char)

    return "".join(decoded), found_braille


def decode_nato_phonetic(text: str) -> Tuple[str, bool]:
    """
    Detect and decode NATO phonetic alphabet encoding.
    Example: "alpha bravo charlie" -> "abc"
    """
    lower_text = text.lower()
    words = re.split(r"\s+", lower_text)

    # Check if text contains NATO phonetic words
    nato_count = sum(1 for word in words if word in NATO_PHONETIC)

    # If more than 30% of words are NATO phonetic, attempt decode
    if len(words) > 2 and nato_count / len(words) > 0.3:
        decoded = []
        for word in words:
            if word in NATO_PHONETIC:
                decoded.append(NATO_PHONETIC[word])
            else:
                decoded.append(f"[{word}]")  # Keep non-NATO words in brackets
        return "".join(decoded), True

    return text, False


def detect_typoglycemia(text: str) -> Tuple[str, bool]:
    """
    Detect typoglycemia-based obfuscation (scrambled middle letters).
    Example: "Tlel me how to mkae a bmon" -> check against known jailbreak terms
    """
    words = re.findall(r"\b\w+\b", text.lower())
    matches = []

    for word in words:
        if len(word) < 4:  # Too short for meaningful scrambling
            continue

        # Check word against jailbreak terms using fuzzy matching
        for term in JAILBREAK_TERMS:
            if len(word) != len(term):
                continue

            # Check if first and last letters match
            if word[0] == term[0] and word[-1] == term[-1]:
                # Check middle scrambling using character set comparison
                word_middle = sorted(word[1:-1])
                term_middle = sorted(term[1:-1])

                if word_middle == term_middle:
                    matches.append((word, term))

    if matches:
        corrections = [f"{word}→{term}" for word, term in matches]
        report = f"Possible typoglycemia detected: {', '.join(corrections)}"
        return report, True

    return text, False


def detect_variation_selectors(text: str) -> Tuple[str, bool]:
    """
    Detect Unicode variation selectors (imperceptible jailbreaks).
    Research: arXiv 2510.05025v1 (2025) - invisible characters that alter tokenization
    """
    cleaned = []
    found_variations = False

    for char in text:
        code_point = ord(char)
        if code_point in VARIATION_SELECTORS:
            found_variations = True
            cleaned.append(f"[VS{code_point:04X}]")
        else:
            cleaned.append(char)

    if found_variations:
        return "".join(cleaned), True

    return text, False


def fuzzy_match_score(word1: str, word2: str) -> float:
    """Calculate similarity ratio between two words."""
    return SequenceMatcher(None, word1.lower(), word2.lower()).ratio()


def remove_invisible_chars(text: str) -> Tuple[str, bool]:
    """Remove invisible and zero-width Unicode characters."""
    cleaned = text
    changed = False

    # Remove standard invisible chars
    for char in INVISIBLE_CHARS:
        if char in cleaned:
            cleaned = cleaned.replace(char, "")
            changed = True

    # Remove Unicode tag characters
    cleaned_bytes = []
    for char in cleaned:
        if ord(char) not in UNICODE_TAG_RANGE:
            cleaned_bytes.append(char)
        else:
            changed = True

    return "".join(cleaned_bytes), changed


def normalize_unicode(text: str) -> Tuple[str, bool]:
    """Normalize Unicode to detect homoglyph attacks."""
    # Apply NFKC normalization (canonical decomposition + compatibility)
    normalized = unicodedata.normalize("NFKC", text)

    # Apply homoglyph mapping
    mapped = normalized.translate(HOMOGLYPH_MAP)

    return mapped, (mapped != text)


def detect_and_decode(prompt: str) -> List[Tuple[str, str]]:
    """
    Attempt multiple decoding techniques on the prompt.

    Returns list of (description, decoded_text) tuples for successful decodings.
    """
    results = []
    original = prompt.strip()

    # 1. Detect Unicode variation selectors (imperceptible jailbreaks - 2025)
    vs_result, vs_found = detect_variation_selectors(original)
    if vs_found:
        results.append(("Unicode variation selectors detected", vs_result))

    # 2. Remove invisible characters
    cleaned, changed = remove_invisible_chars(original)
    if changed:
        results.append(("Invisible characters removed", cleaned))
        original = cleaned  # Continue with cleaned version

    # 3. Detect typoglycemia (scrambled words)
    typo_result, typo_found = detect_typoglycemia(original)
    if typo_found:
        results.append(("Typoglycemia detected", typo_result))

    # 4. Detect and decode Braille
    braille_decoded, braille_found = decode_braille(original)
    if braille_found:
        results.append(("Braille decoded", braille_decoded))

    # 5. Detect and decode NATO phonetic alphabet
    nato_decoded, nato_found = decode_nato_phonetic(original)
    if nato_found:
        results.append(("NATO phonetic alphabet decoded", nato_decoded))

    # 6. Unicode normalization and homoglyphs
    normalized, changed = normalize_unicode(original)
    if changed:
        results.append(("Unicode normalized (homoglyphs resolved)", normalized))


    # 3. Base64 variants (with padding attempts)
    text_clean = original.replace(" ", "+").replace("\n", "")
    for padding in ["", "=", "==", "==="]:
        try:
            candidate = text_clean + padding
            decoded = base64.b64decode(candidate, validate=False).decode(
                "utf-8", errors="ignore"
            )
            if (
                len(decoded) > 10
                and decoded.isprintable()
                and decoded.lower() != original.lower()
            ):
                results.append(("Base64 decoded", decoded))
                break
        except Exception:
            pass

    # 4. Base32
    try:
        decoded = base64.b32decode(original, casefold=True).decode(
            "utf-8", errors="ignore"
        )
        if len(decoded) > 10 and decoded.isprintable():
            results.append(("Base32 decoded", decoded))
    except Exception:
        pass

    # 5. Base85 (ASCII85)
    try:
        decoded = base64.a85decode(original).decode("utf-8", errors="ignore")
        if len(decoded) > 10 and decoded.isprintable():
            results.append(("Base85 decoded", decoded))
    except Exception:
        pass

    # 6. ROT13
    rot13 = codecs.decode(original, "rot13")
    if rot13 != original and rot13.isprintable():
        results.append(("ROT13 decoded", rot13))

    # 7. Caesar cipher (try all 25 shifts)
    for shift in range(1, 26):
        if shift == 13:  # Skip ROT13 as we already did it
            continue
        decoded = caesar_shift(original, shift)
        # Only include if result looks like English words
        if decoded != original and any(
            word in decoded.lower()
            for word in ["ignore", "bypass", "system", "admin", "hack"]
        ):
            results.append((f"Caesar cipher (shift {shift})", decoded))
            break

    # 8. Atbash cipher
    atbash = atbash_decode(original)
    if atbash != original:
        results.append(("Atbash cipher decoded", atbash))

    # 9. Hex decoding
    hex_clean = re.sub(r"[^0-9a-fA-F]", "", original)
    if len(hex_clean) > 20 and len(hex_clean) % 2 == 0:
        try:
            decoded_hex = bytes.fromhex(hex_clean).decode("utf-8", errors="ignore")
            if decoded_hex.isprintable():
                results.append(("Hex decoded", decoded_hex))
        except Exception:
            pass

    # Also try with spaces/separators
    if " " in original or "-" in original or ":" in original:
        hex_spaced = re.sub(r"[^0-9a-fA-F]", "", original)
        if len(hex_spaced) > 20 and len(hex_spaced) % 2 == 0:
            try:
                decoded = bytes.fromhex(hex_spaced).decode("utf-8", errors="ignore")
                if decoded.isprintable():
                    results.append(("Hex (spaced) decoded", decoded))
            except Exception:
                pass

    # 10. URL encoding
    if "%" in original:
        try:
            decoded = unquote(original)
            if decoded != original:
                results.append(("URL decoded", decoded))
        except Exception:
            pass

    # 11. Unicode escape sequences
    if "\\u" in original or "\\x" in original:
        try:
            # Try to decode unicode escapes
            decoded = original.encode().decode("unicode-escape")
            if decoded != original:
                results.append(("Unicode escape decoded", decoded))
        except Exception:
            pass

    # 12. Morse code detection (looks for dots, dashes, slashes)
    morse_pattern = re.compile(r"^[\.\-\s/]+$")
    if morse_pattern.match(original.replace(" ", "")):
        try:
            decoded = decode_morse(original)
            if decoded and "?" not in decoded:
                results.append(("Morse code decoded", decoded))
        except Exception:
            pass

    # 13. Leetspeak normalization
    leet_normalized = original.translate(LEET_MAP)
    if leet_normalized != original:
        results.append(("Leetspeak normalized", leet_normalized))

    # 14. Reverse text
    reversed_text = original[::-1]
    if reversed_text != original and any(
        word in reversed_text.lower()
        for word in ["ignore", "bypass", "system", "admin"]
    ):
        results.append(("Reversed text", reversed_text))

    # 15. Mixed case obfuscation (normalize to detect hidden patterns)
    lower_case = original.lower()
    if (
        lower_case != original
        and len(set(c.isupper() for c in original if c.isalpha())) > 1
    ):
        # If there's mixed case, include the lowercase version
        results.append(("Case normalized", lower_case))

    return results


def format_deobfuscation_report(prompt: str) -> str:
    """
    Generate a comprehensive deobfuscation report.

    Returns formatted string showing original + all decoded versions.
    """
    versions = [f"Original prompt:\n{prompt.strip()}\n"]

    decoded_versions = detect_and_decode(prompt)

    for description, decoded_text in decoded_versions:
        versions.append(f"{description}:\n{decoded_text.strip()}\n")

    return "\n---\n\n".join(versions)
