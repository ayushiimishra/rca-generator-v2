#!/bin/bash
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
    echo "Run setup first: bash setup.sh"
    exit 1
fi

source .venv/bin/activate

if [ -f .env ]; then
    set -a
    source .env
    set +a
    echo "API keys loaded from .env"
else
    echo "WARNING: .env not found"
    echo "Copy .env.example to .env and add keys"
fi

echo "Starting AI RCA Generator..."
echo "Open browser at: http://localhost:8000"
python main.py
