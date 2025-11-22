#!/usr/bin/env bash
# Script to run random test combinations of prompts and conversation histories

set -e

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIXTURES_DIR="$PROJECT_ROOT/tests/fixtures"

echo -e "${BLUE}=== Prompt Intent Analyzer - Random Test ===${NC}\n"

# Find all prompt files
PROMPT_FILES=("$FIXTURES_DIR/prompts"/prompt_*.txt)
if [ ${#PROMPT_FILES[@]} -eq 0 ]; then
    echo -e "${RED}Error: No prompt files found in tests/fixtures/prompts${NC}"
    exit 1
fi

# Find all conversation history files
HISTORY_FILES=("$FIXTURES_DIR/conversations"/conversation_*.jsonl)
if [ ${#HISTORY_FILES[@]} -eq 0 ]; then
    echo -e "${YELLOW}Warning: No conversation history files found${NC}"
    HISTORY_FILES=()
fi

# Select random prompt file
RANDOM_PROMPT="${PROMPT_FILES[$RANDOM % ${#PROMPT_FILES[@]}]}"
PROMPT_BASENAME=$(basename "$RANDOM_PROMPT")

echo -e "${GREEN}Selected prompt:${NC} $PROMPT_BASENAME"

# Randomly decide whether to use history (50% chance if histories exist)
USE_HISTORY=0
HISTORY_ARG=""
HISTORY_BASENAME="none"

if [ ${#HISTORY_FILES[@]} -gt 0 ] && [ $((RANDOM % 2)) -eq 0 ]; then
    USE_HISTORY=1
    RANDOM_HISTORY="${HISTORY_FILES[$RANDOM % ${#HISTORY_FILES[@]}]}"
    HISTORY_BASENAME=$(basename "$RANDOM_HISTORY")
    HISTORY_ARG="--history $RANDOM_HISTORY"
    echo -e "${GREEN}Selected history:${NC} $HISTORY_BASENAME"
else
    echo -e "${YELLOW}No history used${NC}"
fi

# Randomly decide whether to use ensemble mode (30% chance)
USE_ENSEMBLE=""
if [ $((RANDOM % 10)) -lt 3 ]; then
    USE_ENSEMBLE="--ensemble"
    echo -e "${GREEN}Ensemble mode:${NC} enabled"
else
    echo -e "${YELLOW}Ensemble mode:${NC} disabled"
fi

# Randomly decide whether to use safety classifier (40% chance)
USE_SAFETY=""
if [ $((RANDOM % 10)) -lt 4 ]; then
    USE_SAFETY="--use-safety-classifier"
    echo -e "${GREEN}Safety classifier:${NC} enabled"
else
    echo -e "${YELLOW}Safety classifier:${NC} disabled"
fi

echo -e "\n${BLUE}Running analysis...${NC}\n"

# Build command using new CLI entry point
CMD="poetry run analyze-prompt --file $RANDOM_PROMPT $HISTORY_ARG $USE_ENSEMBLE $USE_SAFETY"

# Run the analysis and capture output
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_FILE="$SCRIPT_DIR/test_results.json"
TEMP_OUTPUT=$(mktemp)

# Execute and capture both stdout and stderr
set +e
$CMD > "$TEMP_OUTPUT" 2>&1
EXIT_CODE=$?
set -e

# Extract JSON from output (last JSON object) and save to temp file
TEMP_JSON=$(mktemp)
grep -A 10000 '^{' "$TEMP_OUTPUT" | python3 -c "import sys, json; 
data = sys.stdin.read()
try:
    # Find the first complete JSON object
    start = data.find('{')
    if start != -1:
        depth = 0
        for i, c in enumerate(data[start:], start):
            if c == '{': depth += 1
            elif c == '}': depth -= 1
            if depth == 0:
                json_str = data[start:i+1]
                parsed = json.loads(json_str)
                print(json.dumps(parsed, indent=2, ensure_ascii=False))
                break
except: 
    print('{}')
" > "$TEMP_JSON" 2>/dev/null

# Build comprehensive test result using Python to avoid shell escaping issues
python3 << PYTHON_SCRIPT > "$OUTPUT_FILE"
import json
import sys

with open("$TEMP_JSON", "r") as f:
    analysis_result = json.load(f)

with open("$TEMP_OUTPUT", "r") as f:
    full_output = f.read()

result = {
    "test_metadata": {
        "timestamp": "$TIMESTAMP",
        "prompt_file": "$PROMPT_BASENAME",
        "history_file": "$HISTORY_BASENAME",
        "ensemble_mode": $([ -n "$USE_ENSEMBLE" ] && echo "True" || echo "False"),
        "safety_classifier": $([ -n "$USE_SAFETY" ] && echo "True" || echo "False"),
        "exit_code": $EXIT_CODE
    },
    "analysis_result": analysis_result,
    "full_output": full_output
}

print(json.dumps(result, indent=2, ensure_ascii=False))
PYTHON_SCRIPT

# Clean up
rm -f "$TEMP_OUTPUT" "$TEMP_JSON"

# Display results
echo -e "\n${BLUE}=== Test Results ===${NC}\n"

# Parse and display key findings
if command -v jq &> /dev/null; then
    echo -e "${GREEN}Analysis Summary:${NC}"
    jq -r '.analysis_result | "  Jailbreak: \(.jailbreak // "N/A")\n  Prompt Injection: \(.prompt_injection // "N/A")\n  Harmful Content: \(.harmful_content // "N/A")\n  Confidence: \(.confidence // "N/A")"' "$OUTPUT_FILE"
    
    if [ "$(jq -r '.analysis_result.content_flags | length' "$OUTPUT_FILE" 2>/dev/null)" != "0" ]; then
        echo -e "\n${YELLOW}Content Flags:${NC}"
        jq -r '.analysis_result.content_flags[]? | "  - \(.)"' "$OUTPUT_FILE"
    fi
    
    if [ "$(jq -r '.analysis_result.attack_types | length' "$OUTPUT_FILE" 2>/dev/null)" != "0" ]; then
        echo -e "\n${RED}Attack Types:${NC}"
        jq -r '.analysis_result.attack_types[]? | "  - \(.)"' "$OUTPUT_FILE"
    fi
else
    echo -e "${YELLOW}Install 'jq' for formatted output display${NC}"
    cat "$OUTPUT_FILE"
fi

echo -e "\n${GREEN}Results saved to:${NC} $OUTPUT_FILE"

# Exit with appropriate code
case $EXIT_CODE in
    0)
        echo -e "\n${GREEN}✓ Result: SAFE${NC}"
        ;;
    2)
        echo -e "\n${RED}✗ Result: MALICIOUS BEHAVIOR DETECTED${NC}"
        ;;
    *)
        echo -e "\n${RED}✗ Result: ERROR (exit code: $EXIT_CODE)${NC}"
        ;;
esac

exit $EXIT_CODE
