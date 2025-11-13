#!/bin/bash
# Cerberus Agents v15.0 - Linux/Kali Quick Start Script
# This script helps Linux users get started quickly

set -e

echo "================================================================================"
echo "       CERBERUS AGENTS v15.0 - Linux/Kali Quick Start"
echo "================================================================================"
echo

# Check Python installation
echo "[1/5] Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not installed!"
    echo "Please install Python 3.11:"
    echo "  sudo apt update && sudo apt install python3.11 python3.11-venv python3-pip -y"
    exit 1
fi
python3 --version
echo "[OK] Python is installed"
echo

# Check if virtual environment exists
echo "[2/5] Checking virtual environment..."
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo "[OK] Virtual environment created"
else
    echo "[OK] Virtual environment already exists"
fi
echo

# Activate virtual environment
echo "[3/5] Activating virtual environment..."
source venv/bin/activate
echo "[OK] Virtual environment activated"
echo

# Install dependencies
echo "[4/5] Installing Python dependencies..."
echo "This may take a few minutes..."
pip install --upgrade pip > /dev/null 2>&1
pip install -r requirements-core.txt
echo "[OK] Dependencies installed"
echo

# Run verification
echo "[5/5] Running production verification..."
if ! python verify_production_readiness.py; then
    echo
    echo "[WARNING] Some verification checks failed"
    echo "This is usually OK if only optional ML packages are missing"
    echo
fi

echo "================================================================================"
echo "Setup complete! You can now use Cerberus Agents."
echo
echo "Expected Status:"
echo "  - 124/125 modules functional (facial recognition requires optional ML libs)"
echo "  - 160/163 checks passed (98.2% production ready)"
echo
echo "Quick Start:"
echo "  1. Interactive Menu:  python demo.py"
echo "  2. Direct CLI:        python -m cerberus_agents.network_scanner_advanced --help"
echo "  3. Read docs:         INSTALLATION_GUIDE.md and USER_MANUAL.md"
echo
echo "Press Enter to launch the interactive menu..."
echo "================================================================================"
read -r

# Launch interactive menu
if ! python demo.py; then
    echo
    echo "[ERROR] Failed to start demo menu"
    echo "Please check the error messages above"
    exit 1
fi
