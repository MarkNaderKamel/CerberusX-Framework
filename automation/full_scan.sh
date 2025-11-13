#!/bin/bash
# Cerberus Full Security Scan Automation

set -e

TARGET_NETWORK="${1:-192.168.1.0/24}"
TARGET_DOMAIN="${2:-example.com}"
OUTPUT_DIR="scans_$(date +%Y%m%d_%H%M%S)"

echo "========================================="
echo "Cerberus Full Security Scan"
echo "========================================="
echo "Target Network: $TARGET_NETWORK"
echo "Target Domain: $TARGET_DOMAIN"
echo "Output Directory: $OUTPUT_DIR"
echo ""

mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

echo "[1/7] Running Asset Discovery..."
python -m cerberus_agents.asset_discovery_agent \
  --subnet "$TARGET_NETWORK" \
  --output assets.json

echo "[2/7] Running Reconnaissance..."
python -m cerberus_agents.automated_recon_reporter \
  --target "$TARGET_DOMAIN" \
  --output-dir .

echo "[3/7] Running Credential Audit..."
if [ -f "../samples/users.csv.example" ]; then
  python -m cerberus_agents.credential_checker \
    --users ../samples/users.csv.example \
    --output credentials_audit.json
fi

echo "[4/7] Running Web Vulnerability Scan..."
python -m cerberus_agents.web_vuln_scanner \
  --target "https://$TARGET_DOMAIN" \
  --output web_vuln_scan.json

echo "[5/7] Deploying Honeytokens..."
python -m cerberus_agents.tiny_canary_agent --deploy

echo "[6/7] Collecting Forensics Data..."
python -m cerberus_agents.incident_triage_helper --collect

echo "[7/7] Generating Comprehensive Report..."
python -m cerberus_agents.report_aggregator --scan-dir .

echo ""
echo "========================================="
echo "✅ Full scan complete!"
echo "📁 Results in: $OUTPUT_DIR"
echo "========================================="
