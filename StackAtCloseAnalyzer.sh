#!/bin/bash
# Universal launcher for StackAtClose Analyzer
# Works on Linux and macOS

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Try python3 first, then python
if command -v python3 &> /dev/null; then
    python3 StackAtCloseAnalyzer.py "$@"
elif command -v python &> /dev/null; then
    python StackAtCloseAnalyzer.py "$@"
else
    echo "ERROR: Python 3 is required but not found!"
    echo "Please install Python 3.8 or higher"
    echo ""
    echo "Install instructions:"
    echo "  Ubuntu/Debian: sudo apt install python3 python3-pip"
    echo "  macOS: brew install python3"
    echo "  Or download from: https://python.org"
    exit 1
fi
