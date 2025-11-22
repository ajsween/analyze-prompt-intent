"""
analyzer - Advanced prompt safety analysis toolkit.

A Python package for detecting jailbreak attempts, prompt injections, and harmful content
using local LLM inference via Ollama.
"""

__version__ = "2.0.0"

from analyzer.cli import main
from analyzer.models import AnalysisResult

__all__ = ["main", "AnalysisResult", "__version__"]
