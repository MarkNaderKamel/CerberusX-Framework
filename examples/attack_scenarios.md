# Cerberus Agents - Attack Scenarios & Examples

This document provides practical penetration testing scenarios using Cerberus Agents.

## ⚠️ AUTHORIZATION REQUIRED

All scenarios must be executed with proper written authorization.

---

## Scenario 1: Internal Network Assessment

**Objective**: Discover and assess all assets on internal network

```bash
# 1. Discover assets
python -m cerberus_agents.asset_discovery_agent --subnet 192.168.1.0/24

# 2. Identify weak credentials
python -m cerberus_agents.credential_checker --users internal_users.csv

# 3. Deploy honeytokens for monitoring
python -m cerberus_agents.tiny_canary_agent --deploy

# 4. Monitor for unauthorized access
python -m cerberus_agents.tiny_canary_agent --monitor
```

---

## Scenario 2: Web Application Penetration Test

**Objective**: Identify vulnerabilities in web application

```bash
# 1. Passive reconnaissance
python -m cerberus_agents.automated_recon_reporter --target webapp.company.com

# 2. Active vulnerability scanning
python -m cerberus_agents.web_vuln_scanner --target https://webapp.company.com

# 3. Generate payloads for testing
python -m cerberus_agents.payload_generator --type sqli --output sqli_payloads.json
python -m cerberus_agents.payload_generator --type xss --output xss_payloads.json

# 4. Aggregate results
python -m cerberus_agents.report_aggregator --scan-dir .
```

---

## Scenario 3: Password Security Audit

**Objective**: Assess password security across organization

```bash
# 1. Audit existing credentials
python -m cerberus_agents.credential_checker --users company_users.csv

# 2. Attempt to crack weak hashes (authorized)
python -m cerberus_agents.hash_cracker \
  --hash 5f4dcc3b5aa765d61d8327deb882cf99 \
  --type md5 \
  --wordlist /usr/share/wordlists/rockyou.txt

# 3. Generate report with recommendations
python -m cerberus_agents.report_aggregator --scan-dir .
```

---

## Scenario 4: Incident Response & Forensics

**Objective**: Collect forensics data after security incident

```bash
# 1. Collect system forensics
python -m cerberus_agents.incident_triage_helper --collect

# 2. Deploy honeytokens to detect lateral movement
python -m cerberus_agents.tiny_canary_agent --deploy

# 3. Monitor for further compromise
python -m cerberus_agents.tiny_canary_agent --monitor --interval 30
```

---

## Scenario 5: External Penetration Test

**Objective**: Test external perimeter from attacker perspective

```bash
# 1. Passive information gathering
python -m cerberus_agents.automated_recon_reporter --target company.com

# 2. Identify externally facing assets
python -m cerberus_agents.asset_discovery_agent --subnet PUBLIC_IP_RANGE

# 3. Vulnerability assessment
python -m cerberus_agents.web_vuln_scanner --target https://www.company.com

# 4. Comprehensive report
python -m cerberus_agents.report_aggregator --scan-dir .
```

---

## Scenario 6: Post-Exploitation

**Objective**: Maintain access and escalate privileges (authorized)

```bash
# 1. Generate reverse shell payloads
python -m cerberus_agents.payload_generator \
  --type reverse_shell \
  --ip 10.0.0.1 \
  --port 4444 \
  --shell-type all

# 2. Generate web shells
python -m cerberus_agents.payload_generator \
  --type web_shell \
  --shell-type all

# 3. Privilege escalation prep
python -m cerberus_agents.payload_generator --type lfi
```

---

## Scenario 7: Continuous Security Monitoring

**Objective**: Ongoing security assessment and threat detection

```bash
# Use automation script
./automation/continuous_monitoring.sh 3600  # Run every hour

# Or manually:
# Start collector server
python -m cerberus_agents.central_collector --start --port 8443 &

# Deploy agents on multiple systems
# Each agent sends reports to collector
```

---

## Scenario 8: Red Team Exercise

**Objective**: Full attack simulation (authorized)

```bash
# Phase 1: Reconnaissance
python -m cerberus_agents.automated_recon_reporter --target target.com

# Phase 2: Initial Access
python -m cerberus_agents.web_vuln_scanner --target https://target.com
python -m cerberus_agents.payload_generator --type reverse_shell --ip ATTACKER_IP --port 443

# Phase 3: Credential Harvesting
python -m cerberus_agents.credential_checker --users harvested_creds.csv
python -m cerberus_agents.hash_cracker --hash CAPTURED_HASH --type sha256

# Phase 4: Persistence
python -m cerberus_agents.payload_generator --type web_shell

# Phase 5: Forensics Collection
python -m cerberus_agents.incident_triage_helper --collect

# Final: Comprehensive Report
python -m cerberus_agents.report_aggregator --scan-dir .
```

---

## Integration with External Tools

### Nmap Integration
```bash
# Configure in config/pentest_tasks.json
python -m cerberus_agents.pentest_task_runner --config config/pentest_tasks.json
```

### Metasploit Integration
```bash
# Use payload generator for compatible payloads
python -m cerberus_agents.payload_generator --type reverse_shell --ip IP --port PORT
```

### Burp Suite Integration
```bash
# Export payloads for Burp testing
python -m cerberus_agents.payload_generator --type sqli --output burp_sqli.json
python -m cerberus_agents.payload_generator --type xss --output burp_xss.json
```

---

## Best Practices

1. **Always obtain written authorization** before testing
2. **Define scope clearly** in allowed_targets.yml
3. **Log all activities** for audit trail
4. **Handle data securely** - encrypt sensitive findings
5. **Communicate findings** - use report aggregator
6. **Follow responsible disclosure** timeline
7. **Document everything** - maintain detailed notes
8. **Backup evidence** - preserve forensics data
9. **Test in staging** before production testing
10. **Have incident response plan** ready

---

## Cleanup After Testing

```bash
# Remove honeytokens
rm -rf honeytokens/

# Archive scan results
tar -czf scan_results_$(date +%Y%m%d).tar.gz *.json *.html

# Clear temporary data
rm -f *.json *.html

# Stop collector
pkill -f central_collector
```

---

**Remember**: These are authorized penetration testing scenarios only.
Unauthorized use is illegal and unethical.
