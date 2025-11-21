#!/usr/bin/env bash
# Script to run analyze_prompt.py using Poetry

set -e

# Check if poetry is installed
if ! command -v poetry &> /dev/null; then
    echo "Error: Poetry is not installed. Please install it first."
    echo "Visit: https://python-poetry.org/docs/#installation"
    exit 1
fi

# Install dependencies if needed
echo "Checking dependencies..."
poetry install --no-interaction

# Check if LM-Studio is running
echo "Checking if LM-Studio is running..."
if ! curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:1234/v1/models | grep -q "200"; then
    echo "Warning: LM-Studio does not appear to be running at http://127.0.0.1:1234"
    echo "Please start LM-Studio before running this script."
    exit 1
fi

# Run the Python script with poetry, passing all arguments
poetry run python analyze_prompt.py "$@"
