#!/bin/bash
# Cerberus Continuous Security Monitoring

INTERVAL="${1:-3600}"  # Default: 1 hour

echo "========================================="
echo "Cerberus Continuous Monitoring"
echo "========================================="
echo "Interval: $INTERVAL seconds"
echo "Press Ctrl+C to stop"
echo ""

while true; do
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    echo "[$TIMESTAMP] Running security checks..."
    
    # Monitor honeytokens
    python -m cerberus_agents.tiny_canary_agent --monitor --interval 60 &
    MONITOR_PID=$!
    
    # Run periodic scans
    python -m cerberus_agents.automated_recon_reporter --target example.com
    
    # Aggregate reports
    python -m cerberus_agents.report_aggregator --scan-dir .
    
    echo "[$TIMESTAMP] Checks complete. Sleeping for $INTERVAL seconds..."
    sleep "$INTERVAL"
done
