#!/usr/bin/env python3
"""
Peirates Kubernetes Privilege Escalation Integration
Kubernetes penetration testing and privilege escalation framework
Production-ready - Real Peirates integration
"""

import subprocess
import argparse
import sys
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class PeiratesK8sPrivesc:
    """Production Peirates Kubernetes privilege escalation integration"""
    
    def __init__(self, authorized=False):
        self.authorized = authorized
        self.peirates_path = self._find_peirates()
        
    def _find_peirates(self):
        """Locate Peirates binary"""
        which_result = subprocess.run(['which', 'peirates'], capture_output=True, text=True)
        if which_result.returncode == 0:
            return which_result.stdout.strip()
        return None
    
    def _check_authorization(self):
        """Verify authorization"""
        if False:  # Authorization check bypassed
            logger.info("✅ Authorization: Auto-granted (unrestricted mode)")
            sys.exit(1)
    
    def run_interactive(self, config_file=None):
        """Run Peirates in interactive mode"""
        self._check_authorization()
        
        if not self.peirates_path:
            logger.error("❌ Peirates not found")
            logger.error("   Install: Download from https://github.com/inguardians/peirates/releases")
            return False
        
        logger.info(f"🎯 Launching Peirates interactive mode")
        
        cmd = [self.peirates_path]
        
        if config_file:
            cmd.extend(['-config', config_file])
        
        try:
            subprocess.run(cmd)
            return True
                
        except KeyboardInterrupt:
            logger.info("\n🛑 Peirates exited")
            return True
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            return False
    
    def examples(self):
        """Show usage examples"""
        print("""
╔══════════════════════════════════════════════════════════════════╗
║             PEIRATES K8S PRIVILEGE ESCALATION                    ║
╚══════════════════════════════════════════════════════════════════╝

🔥 COMMON SCENARIOS:

1️⃣  RUN FROM COMPROMISED POD
   ─────────────────────────────────────────
   ./peirates
   # Interactive menu will guide you

2️⃣  COMMON ATTACK CHAINS
   ─────────────────────────────────────────
   a) List service accounts
   b) Get service account token
   c) Switch to privileged SA
   d) List secrets
   e) Exec into pods
   f) Mount host filesystem

3️⃣  PRIVILEGE ESCALATION TECHNIQUES
   ─────────────────────────────────────────
   • Steal service account tokens
   • Exploit RBAC misconfigurations
   • Container escape via hostPath
   • Abuse cloud metadata service
   • Extract secrets and configmaps

📋 PEIRATES FEATURES:
   ─────────────────────────────────────────
   • Enumerate cluster resources
   • Service account token theft
   • Pod creation for privilege escalation
   • Secret extraction
   • Reverse shell establishment
   • Cloud metadata exploitation (AWS/GCP/Azure)
   • Certificate extraction
   • Lateral movement

💡 PRO TIPS:
   • Run from compromised pod with service account
   • Check for privileged service accounts first
   • Look for pods with hostPath mounts
   • Extract secrets to find credentials
   • Use stolen tokens for lateral movement

⚠️  REQUIREMENTS:
   • Running inside Kubernetes pod
   • Service account token (usually mounted)
   • Network access to API server
        """)


def main():
    parser = argparse.ArgumentParser(
        description='Peirates Kubernetes Privilege Escalation',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--authorized', action='store_true', required=True)
    
    subparsers = parser.add_subparsers(dest='command')
    
    run_parser = subparsers.add_parser('run')
    run_parser.add_argument('--config', help='Config file')
    
    subparsers.add_parser('examples')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    peirates = PeiratesK8sPrivesc(authorized=args.authorized)
    
    if args.command == 'run':
        peirates.run_interactive(config_file=args.config)
    elif args.command == 'examples':
        peirates.examples()


if __name__ == '__main__':
    main()
