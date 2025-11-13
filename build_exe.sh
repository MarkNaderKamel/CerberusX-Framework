#!/bin/bash
# Cerberus Agents - EXE Build Script (Linux/macOS)

set -e

echo "========================================="
echo "Cerberus Agents - EXE Builder"
echo "========================================="
echo ""

if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

echo "Activating virtual environment..."
source venv/bin/activate

echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo ""
echo "Building executables with PyInstaller..."
echo ""

mkdir -p dist

AGENTS=(
    "asset_discovery_agent"
    "automated_recon_reporter"
    "credential_checker"
    "tiny_canary_agent"
    "pentest_task_runner"
    "incident_triage_helper"
    "central_collector"
)

for agent in "${AGENTS[@]}"; do
    echo "Building ${agent}..."
    pyinstaller --onefile \
                --name="${agent}" \
                --clean \
                --distpath="dist" \
                --workpath="build/${agent}" \
                --specpath="build" \
                "cerberus_agents/${agent}.py"
    echo "✓ ${agent} built successfully"
    echo ""
done

echo "========================================="
echo "Build Complete!"
echo "========================================="
echo ""
echo "Executables are in the 'dist' directory:"
ls -lh dist/
echo ""
echo "To code-sign executables (macOS):"
echo "  codesign -s 'Developer ID' dist/agent_name"
echo ""
echo "To code-sign executables (Windows):"
echo "  signtool sign /f certificate.pfx /p password dist/agent_name.exe"
echo ""
