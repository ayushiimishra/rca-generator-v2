#!/bin/bash
set -e
echo "=================================================="
echo " AI RCA Generator — Setup"
echo "=================================================="

OS="unknown"
if [ -f /etc/fedora-release ]; then
    OS="fedora"
elif [ -f /etc/debian_version ]; then
    OS="debian"
elif grep -qi microsoft /proc/version 2>/dev/null; then
    OS="wsl"
fi
echo "Detected OS: $OS"

if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

source .venv/bin/activate
echo "Installing Python dependencies..."
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo "Dependencies installed"

mkdir -p uploads
mkdir -p rca_memory

if [ ! -f "chainsaw/chainsaw" ]; then
    echo "Downloading Chainsaw..."
    mkdir -p chainsaw
    cd chainsaw
    wget -q --show-progress \
        https://github.com/WithSecureLabs/chainsaw/releases/download/v2.9.0/chainsaw_x86_64-unknown-linux-gnu.tar.gz \
        -O chainsaw.tar.gz
    tar -xzf chainsaw.tar.gz
    chmod +x chainsaw
    rm -f chainsaw.tar.gz
    cd ..
    echo "Chainsaw installed"
else
    echo "Chainsaw already present"
fi

if [ ! -d "sigma-rules" ]; then
    echo "Downloading Sigma rules..."
    git clone --depth 1 \
        https://github.com/SigmaHQ/sigma \
        sigma-rules -q
    echo "Sigma rules downloaded"
else
    echo "Sigma rules already present"
fi

if [ ! -f ".env" ]; then
    cp .env.example .env
    echo ""
    echo "Created .env from .env.example"
    echo "IMPORTANT: Edit .env and add your GEMINI_API_KEY"
    echo "Get free key from: https://aistudio.google.com"
else
    echo ".env already exists"
fi

echo ""
echo "=================================================="
echo " Setup complete"
echo " Next: edit .env then run: bash start.sh"
echo "=================================================="
