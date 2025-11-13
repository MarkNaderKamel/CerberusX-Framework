#!/bin/bash
# Cerberus Quick Security Scan

TARGET="${1:-example.com}"

echo "========================================="
echo "Cerberus Quick Scan: $TARGET"
echo "========================================="

echo "[1/3] Reconnaissance..."
python -m cerberus_agents.automated_recon_reporter --target "$TARGET"

echo "[2/3] Web Vulnerability Scan..."
python -m cerberus_agents.web_vuln_scanner --target "https://$TARGET"

echo "[3/3] Generating Report..."
python -m cerberus_agents.report_aggregator --scan-dir .

echo "✅ Quick scan complete!"
