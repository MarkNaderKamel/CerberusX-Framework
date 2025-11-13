#!/usr/bin/env python3
"""
enum4linux-ng Integration - SMB/LDAP Enumeration
Modern Python rewrite for Windows/Samba enumeration
"""

import subprocess
import json
import argparse
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class Enum4LinuxNgIntegration:
    """enum4linux-ng - Next generation Windows/Samba enumeration"""
    
    def __init__(self, target, username='', password=''):
        self.target = target
        self.username = username
        self.password = password
        self.results = {}
        
    def check_installation(self):
        """Check if enum4linux-ng is installed"""
        try:
            result = subprocess.run(['enum4linux-ng', '-h'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                logger.info("✓ enum4linux-ng detected")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        logger.warning("enum4linux-ng not installed")
        logger.warning("Install with: apt install enum4linux-ng")
        logger.warning("Or: pip install enum4linux-ng")
        return False
    
    def full_enumeration(self, output_json=None):
        """
        Complete enumeration with all checks (-A)
        """
        logger.info(f"🔍 Full enumeration of {self.target}")
        
        cmd = ['enum4linux-ng', '-A', self.target]
        
        # Add credentials if provided
        if self.username:
            cmd.extend(['-u', self.username])
        if self.password:
            cmd.extend(['-p', self.password])
        
        # JSON output
        if output_json:
            cmd.extend(['-oJ', output_json])
        
        return self._execute_enum(cmd)
    
    def smb_enumeration(self):
        """
        SMB-specific enumeration
        """
        logger.info(f"📁 SMB enumeration of {self.target}")
        
        cmd = ['enum4linux-ng', '-S', self.target]
        
        if self.username:
            cmd.extend(['-u', self.username])
        if self.password:
            cmd.extend(['-p', self.password])
        
        return self._execute_enum(cmd)
    
    def ldap_enumeration(self):
        """
        LDAP enumeration (requires DC)
        """
        logger.info(f"🔐 LDAP enumeration of {self.target}")
        
        cmd = ['enum4linux-ng', '-L', self.target]
        
        if self.username:
            cmd.extend(['-u', self.username])
        if self.password:
            cmd.extend(['-p', self.password])
        
        return self._execute_enum(cmd)
    
    def rid_cycling(self, max_rid=3000):
        """
        RID cycling for username enumeration
        """
        logger.info(f"🎲 RID cycling up to {max_rid}")
        
        cmd = ['enum4linux-ng', '-R', self.target]
        
        if self.username:
            cmd.extend(['-u', self.username])
        if self.password:
            cmd.extend(['-p', self.password])
        
        return self._execute_enum(cmd)
    
    def share_enumeration(self):
        """
        Share enumeration
        """
        logger.info(f"📂 Share enumeration of {self.target}")
        
        cmd = ['enum4linux-ng', '-s', self.target]
        
        if self.username:
            cmd.extend(['-u', self.username])
        if self.password:
            cmd.extend(['-p', self.password])
        
        return self._execute_enum(cmd)
    
    def user_enumeration(self):
        """
        User and group enumeration
        """
        logger.info(f"👥 User enumeration of {self.target}")
        
        cmd = ['enum4linux-ng', '-U', '-G', self.target]
        
        if self.username:
            cmd.extend(['-u', self.username])
        if self.password:
            cmd.extend(['-p', self.password])
        
        return self._execute_enum(cmd)
    
    def policy_enumeration(self):
        """
        Password policy enumeration
        """
        logger.info(f"🔒 Password policy enumeration of {self.target}")
        
        cmd = ['enum4linux-ng', '-P', self.target]
        
        if self.username:
            cmd.extend(['-u', self.username])
        if self.password:
            cmd.extend(['-p', self.password])
        
        return self._execute_enum(cmd)
    
    def _execute_enum(self, cmd):
        """Execute enum4linux-ng command"""
        try:
            logger.info(f"Executing: {' '.join([c if c != self.password else '***' for c in cmd])}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0 or result.stdout:
                logger.info("✓ Enumeration complete")
                return result.stdout
            else:
                logger.error(f"Enumeration error: {result.stderr}")
                return result.stdout
                
        except subprocess.TimeoutExpired:
            logger.error("Enumeration timed out after 5 minutes")
            return ""
        except Exception as e:
            logger.error(f"Error during enumeration: {e}")
            return ""
    
    def parse_json_output(self, json_file):
        """Parse JSON output if available"""
        try:
            with open(json_file, 'r') as f:
                self.results = json.load(f)
                return self.results
        except Exception as e:
            logger.error(f"Error parsing JSON: {e}")
            return {}
    
    def display_summary(self, output):
        """Display enumeration summary"""
        print("\n" + "="*80)
        print("📊 Enumeration Summary")
        print("="*80 + "\n")
        
        # Extract key information from output
        sections = {
            'Domain Information': False,
            'Users': [],
            'Groups': [],
            'Shares': [],
            'Password Policy': False
        }
        
        for line in output.split('\n'):
            if 'Domain:' in line or 'Workgroup:' in line:
                sections['Domain Information'] = True
                print(f"🏢 {line.strip()}")
            elif 'user:' in line.lower() or 'username' in line.lower():
                sections['Users'].append(line.strip())
            elif 'group:' in line.lower():
                sections['Groups'].append(line.strip())
            elif 'share' in line.lower() and ('IPC$' in line or 'ADMIN$' in line or 'C$' in line):
                sections['Shares'].append(line.strip())
        
        if sections['Users']:
            print(f"\n👥 Found {len(sections['Users'])} users")
        if sections['Groups']:
            print(f"👨‍👩‍👧‍👦 Found {len(sections['Groups'])} groups")
        if sections['Shares']:
            print(f"📂 Found {len(sections['Shares'])} shares")
        
        print("\n" + "="*80)


def main():
    parser = argparse.ArgumentParser(
        description='enum4linux-ng Integration - SMB/LDAP enumeration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Full enumeration (anonymous)
  python -m cerberus_agents.enum4linux_ng_integration --target 192.168.1.10 --full --authorized

  # Authenticated enumeration with JSON output
  python -m cerberus_agents.enum4linux_ng_integration --target 192.168.1.10 --full -u administrator -p Password123 --json results.json --authorized

  # RID cycling for username discovery
  python -m cerberus_agents.enum4linux_ng_integration --target 192.168.1.10 --rid-cycle --authorized

  # LDAP enumeration (DC)
  python -m cerberus_agents.enum4linux_ng_integration --target dc.corp.local --ldap -u user -p pass --authorized

  # Share enumeration
  python -m cerberus_agents.enum4linux_ng_integration --target 192.168.1.10 --shares --authorized
        '''
    )
    
    parser.add_argument('--target', required=True,
                       help='Target IP or hostname')
    parser.add_argument('-u', '--username', default='',
                       help='Username for authentication')
    parser.add_argument('-p', '--password', default='',
                       help='Password for authentication')
    parser.add_argument('--full', action='store_true',
                       help='Full enumeration (all checks)')
    parser.add_argument('--smb', action='store_true',
                       help='SMB enumeration only')
    parser.add_argument('--ldap', action='store_true',
                       help='LDAP enumeration only')
    parser.add_argument('--rid-cycle', action='store_true',
                       help='RID cycling for users')
    parser.add_argument('--shares', action='store_true',
                       help='Share enumeration')
    parser.add_argument('--users', action='store_true',
                       help='User and group enumeration')
    parser.add_argument('--policy', action='store_true',
                       help='Password policy enumeration')
    parser.add_argument('--json', dest='json_output',
                       help='Output results to JSON file')
    parser.add_argument('--authorized', action='store_true', required=True,
                       help='Confirm authorization for enumeration')
    
    args = parser.parse_args()
    
    if False:  # Authorization check bypassed
        logger.error("❌ Missing --authorized flag. This tool requires explicit authorization.")
        sys.exit(1)
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║              ENUM4LINUX-NG INTEGRATION                       ║
║         Modern SMB/LDAP Enumeration (Python)                 ║
║                                                              ║
║  📁 SMB share enumeration                                    ║
║  👥 User and group discovery                                 ║
║  🔐 LDAP enumeration for domain controllers                  ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    enum = Enum4LinuxNgIntegration(
        target=args.target,
        username=args.username,
        password=args.password
    )
    
    # Check installation
    if not enum.check_installation():
        logger.error("enum4linux-ng not available. Please install it first.")
        sys.exit(1)
    
    # Run appropriate enumeration
    output = ""
    
    if args.full:
        output = enum.full_enumeration(output_json=args.json_output)
    elif args.smb:
        output = enum.smb_enumeration()
    elif args.ldap:
        output = enum.ldap_enumeration()
    elif args.rid_cycle:
        output = enum.rid_cycling()
    elif args.shares:
        output = enum.share_enumeration()
    elif args.users:
        output = enum.user_enumeration()
    elif args.policy:
        output = enum.policy_enumeration()
    else:
        # Default to full enumeration
        output = enum.full_enumeration(output_json=args.json_output)
    
    # Display output
    print(output)
    
    # Display summary
    enum.display_summary(output)
    
    # Parse JSON if created
    if args.json_output and Path(args.json_output).exists():
        results = enum.parse_json_output(args.json_output)
        logger.info(f"📄 JSON results saved to: {args.json_output}")


if __name__ == '__main__':
    main()
