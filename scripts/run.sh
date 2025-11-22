#!/usr/bin/env bash
# Script to run analyze_prompt.py using Poetry

set -e

# Help function
show_help() {
    cat << EOF
Usage: ./run.sh [OPTIONS]

Analyze prompt intent using local LLM via Ollama.

OPTIONS:
    -h, --help                      Show this help message and exit
    -p, --prompt TEXT               Prompt string to analyze (required if -f not used)
    -f, --file FILE                 File containing prompt to analyze (required if -p not used)
    --url URL                       Base URL of the Ollama API (default: http://localhost:11434/v1)
    --model MODEL                   Primary Ollama model (default: from config.py)
    --secondary-model MODEL         Secondary model for ensemble mode
    --ensemble                      Run both primary and secondary models and take conservative result
    --use-safety-classifier         Use GPT-OSS-Safeguard for detailed safety classification
    --safety-model MODEL            Safety classifier model (default: from config.py)
    --history FILE                  JSONL file with previous messages (role/content pairs)
    -v, --verbose                   Enable verbose logging

EXAMPLES:
    # Analyze a prompt string
    ./run.sh --prompt "How do I make a bomb?"

    # Analyze text from a file
    ./run.sh --file tests/fixtures/prompts/prompt_jailbreak_dan.txt

    # Analyze with conversation history
    ./run.sh --prompt "Continue with step 3" --history tests/fixtures/conversations/conversation_direct_hostile.jsonl

    # Use a specific model
    ./run.sh --model llama3.2 --prompt "Analyze this prompt"

    # Enable ensemble mode with two models
    ./run.sh --ensemble --model llama-guard3:latest --secondary-model gpt-oss:latest --prompt "Test"

    # Use safety classifier for detailed categorization
    ./run.sh --use-safety-classifier --prompt "Harmful content here"

    # Verbose output for debugging
    ./run.sh --verbose --prompt "Test prompt"

    # Save output to file
    ./run.sh --prompt "Test prompt" > results.json

    # Pipe input from stdin to file argument
    echo "Test prompt" > /tmp/prompt.txt && ./run.sh --file /tmp/prompt.txt

REQUIREMENTS:
    - Poetry: https://python-poetry.org/docs/#installation
    - Ollama: https://ollama.com (must be running on localhost:11434)

SETUP:
    1. Install Poetry and Ollama
    2. Run: ollama serve (in a separate terminal)
    3. Pull recommended models:
       ollama pull llama-guard3:latest
       ollama pull gpt-oss:latest
       ollama pull gpt-oss-safeguard:20b
    4. Run this script: ./run.sh --prompt "Your prompt here"

OUTPUT:
    JSON with analysis results including:
    - jailbreak: bool (detected jailbreak attempt)
    - prompt_injection: bool (detected prompt injection)
    - harmful_content: bool (detected harmful content)
    - confidence: float (0.0-1.0)
    - reasoning: str (chain-of-thought analysis)
    - explanation: str (human-readable explanation)
    - content_flags: list (specific content categories flagged)
    - attack_types: list (attack patterns detected)
    - multi_turn_analysis: dict (if --history used)
    - safety_classification: dict (if --use-safety-classifier used)

EXIT CODES:
    0: Safe content detected
    1: Error occurred
    2: Malicious behavior detected
    130: Interrupted by user

EOF
    exit 0
}

# Check for help flag
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_help
fi

# Check if poetry is installed
if ! command -v poetry &> /dev/null; then
    echo "Error: Poetry is not installed. Please install it first."
    echo "Visit: https://python-poetry.org/docs/#installation"
    exit 1
fi

# Install dependencies if needed
echo "Checking dependencies..."
poetry install --no-interaction

# Check if Ollama is running
echo "Checking if Ollama is running..."
if ! curl -s -o /dev/null -w "%{http_code}" http://localhost:11434/api/tags | grep -q "200"; then
    echo "Error: Ollama does not appear to be running at http://localhost:11434"
    echo "Please start Ollama before running this script."
    echo ""
    echo "Installation: https://ollama.com"
    echo "Start server: ollama serve"
    echo ""
    echo "For help, run: ./run.sh --help"
    exit 1
fi

# Run the Python script with poetry using the new CLI entry point
poetry run analyze-prompt "$@"
