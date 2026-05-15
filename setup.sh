#!/bin/bash

# GuessWho - Quick Setup Script

echo "==================================="
echo "GuessWho - User Enumeration Tool"
echo "==================================="
echo ""

# Check Python version
echo "[*] Checking Python version..."
if ! command -v python3 &> /dev/null; then
    echo "[!] Python 3 is not installed. Please install Python 3.7 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "[+] Found Python $PYTHON_VERSION"

# Check if pip is installed
if ! command -v pip3 &> /dev/null; then
    echo "[!] pip3 is not installed. Please install pip."
    exit 1
fi

# Install dependencies
echo ""
echo "[*] Installing dependencies..."
pip3 install -r requirements.txt

if [ $? -eq 0 ]; then
    echo "[+] Dependencies installed successfully!"
else
    echo "[!] Failed to install dependencies."
    exit 1
fi

# Make main script executable
chmod +x guesswho.py

echo ""
echo "[+] Setup complete!"
echo ""
echo "Quick Start:"
echo "  python3 guesswho.py -u 'http://example.com/login' -w wordlists/usernames.txt -d 'username=FUZZ&password=test'"
echo ""
echo "For more examples, see examples.txt"
echo "For full documentation, see README.md"
echo ""
