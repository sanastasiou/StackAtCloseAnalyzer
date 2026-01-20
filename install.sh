#!/bin/bash
# Cross-platform installer for StackAtClose Analyzer

set -e

echo "StackAtClose Analyzer - Dependency Installer"
echo "============================================="

# Detect OS
OS="unknown"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "win32" ]]; then
    OS="windows"
fi
echo "Detected OS: $OS"

# Find Python 3
PYTHON=""
for cmd in python3 python; do
    if command -v $cmd &> /dev/null; then
        major=$($cmd -c "import sys; print(sys.version_info.major)" 2>/dev/null)
        if [[ "$major" == "3" ]]; then
            PYTHON=$cmd
            echo "Found: $PYTHON ($($PYTHON --version))"
            break
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    echo "ERROR: Python 3 not found!"
    echo "Install from: https://www.python.org/downloads/"
    exit 1
fi

# Install tkinter on Linux if needed
if [[ "$OS" == "linux" ]]; then
    if ! $PYTHON -c "import tkinter" 2>/dev/null; then
        echo "Installing Tkinter..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y python3-tk
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y python3-tkinter
        elif command -v pacman &> /dev/null; then
            sudo pacman -S --noconfirm tk
        fi
    fi
fi

# Install Python packages
echo "Installing Python dependencies..."
$PYTHON -m pip install --upgrade pip
$PYTHON -m pip install scapy>=2.6.0 matplotlib>=3.7.0 numpy>=1.24.0

echo ""
echo "Done! Run: ./run.sh [your_trace.pcapng]"
