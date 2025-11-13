# Cerberus Agents - Practical Examples

## Quick Start Examples

### Example 1: Scan Your Network (Simple)
```bash
# Discover all active hosts
python -m cerberus_agents.asset_discovery_agent --subnet 192.168.1.0/24

# Results will be in assets.json
```

### Example 2: Test a Website
```bash
# Passive recon
python -m cerberus_agents.automated_recon_reporter --target example.com

# Active vulnerability scan
python -m cerberus_agents.web_vuln_scanner --target https://example.com

# View results in HTML report
```

### Example 3: Audit Passwords
```bash
# Check password strength
python -m cerberus_agents.credential_checker --users samples/users.csv.example

# Results in credentials_audit.json with recommendations
```

### Example 4: Generate Exploit Payloads
```bash
# Reverse shell (for authorized testing)
python -m cerberus_agents.payload_generator \
  --type reverse_shell \
  --ip 10.0.0.1 \
  --port 4444

# SQL injection payloads
python -m cerberus_agents.payload_generator --type sqli

# XSS payloads
python -m cerberus_agents.payload_generator --type xss
```

### Example 5: Crack a Hash
```bash
# Crack MD5 hash
python -m cerberus_agents.hash_cracker \
  --hash 5f4dcc3b5aa765d61d8327deb882cf99 \
  --type md5

# Result: password
```

### Example 6: Deploy Honeytokens
```bash
# Deploy canary files
python -m cerberus_agents.tiny_canary_agent --deploy

# Monitor for access (runs continuously)
python -m cerberus_agents.tiny_canary_agent --monitor
```

### Example 7: Collect Forensics
```bash
# Incident response data collection
python -m cerberus_agents.incident_triage_helper --collect

# Creates forensics bundle with chain of custody
```

### Example 8: Aggregate All Reports
```bash
# After running multiple scans
python -m cerberus_agents.report_aggregator --scan-dir .

# Creates comprehensive HTML report
```

## Advanced Examples

### Full Penetration Test Workflow
```bash
# 1. Reconnaissance
python -m cerberus_agents.automated_recon_reporter --target target.com

# 2. Asset discovery
python -m cerberus_agents.asset_discovery_agent --subnet 192.168.1.0/24

# 3. Vulnerability scanning
python -m cerberus_agents.web_vuln_scanner --target https://target.com

# 4. Credential testing
python -m cerberus_agents.credential_checker --users harvested_users.csv

# 5. Generate comprehensive report
python -m cerberus_agents.report_aggregator --scan-dir .
```

### Automated Daily Security Scan
```bash
#!/bin/bash
# Save as daily_scan.sh

DATE=$(date +%Y%m%d)
mkdir -p scans/$DATE

python -m cerberus_agents.automated_recon_reporter --target company.com
python -m cerberus_agents.web_vuln_scanner --target https://www.company.com
python -m cerberus_agents.report_aggregator --scan-dir scans/$DATE
```

### Continuous Honeytoken Monitoring
```bash
# Terminal 1: Deploy honeytokens
python -m cerberus_agents.tiny_canary_agent --deploy

# Terminal 2: Monitor (runs forever)
python -m cerberus_agents.tiny_canary_agent --monitor --interval 60
```

### Central Report Collection Setup
```bash
# Server: Start collector
python -m cerberus_agents.central_collector --start --port 8443

# Agents: Send reports
curl -X POST http://collector-server:8443/api/report \
  -H 'X-API-Key: YOUR_API_KEY' \
  -H 'Content-Type: application/json' \
  -d @scan_results.json
```

## Tips & Tricks

### 1. Use Automation Scripts
```bash
# Full scan
./automation/full_scan.sh 192.168.1.0/24 example.com

# Quick scan
./automation/quick_scan.sh example.com

# Continuous monitoring
./automation/continuous_monitoring.sh 3600
```

### 2. Export Results to Different Formats
```bash
# JSON for processing
python -m cerberus_agents.asset_discovery_agent --output results.json

# HTML for reports
python -m cerberus_agents.automated_recon_reporter --target example.com
# Automatically creates HTML report
```

### 3. Combine with External Tools
```bash
# Use Nmap results
nmap -sV 192.168.1.0/24 -oX nmap.xml
# Process with task runner

# Integrate with Metasploit
python -m cerberus_agents.payload_generator --type reverse_shell
# Copy payload to msf
```

### 4. Customize Payloads
```bash
# Generate all shell types
python -m cerberus_agents.payload_generator \
  --type reverse_shell \
  --shell-type all \
  --ip YOUR_IP \
  --port YOUR_PORT

# Save to file
python -m cerberus_agents.payload_generator \
  --type sqli \
  --output custom_payloads.json
```

### 5. Efficient Hash Cracking
```bash
# Use custom wordlist
python -m cerberus_agents.hash_cracker \
  --hash HASH_HERE \
  --type md5 \
  --wordlist /path/to/wordlist.txt

# Brute force (limited)
python -m cerberus_agents.hash_cracker \
  --hash HASH_HERE \
  --type md5 \
  --brute-force 5
```

## Common Workflows

### Workflow 1: New Target Assessment
1. Passive recon → automated_recon_reporter
2. Active scan → web_vuln_scanner
3. Review findings → report_aggregator
4. Deploy monitoring → tiny_canary_agent

### Workflow 2: Password Security Review
1. Collect hashes → credential_checker
2. Attempt cracking → hash_cracker
3. Generate report → report_aggregator
4. Provide recommendations

### Workflow 3: Incident Investigation
1. Collect forensics → incident_triage_helper
2. Deploy detection → tiny_canary_agent
3. Monitor activity → canary monitoring
4. Document findings

### Workflow 4: Red Team Exercise
1. Recon → automated_recon_reporter
2. Vulnerability discovery → web_vuln_scanner
3. Exploitation → payload_generator
4. Persistence → deploy web shells
5. Exfiltration → data collection
6. Report → report_aggregator
