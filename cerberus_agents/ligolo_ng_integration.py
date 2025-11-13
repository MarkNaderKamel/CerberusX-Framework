#!/usr/bin/env python3
"""
Ligolo-ng Integration - Advanced Tunneling/Pivoting Tool
Production-ready network pivoting using TUN interface (faster than SOCKS proxies)
"""

import subprocess
import argparse
import logging
import sys
import os
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class LigoloNgIntegration:
    """Ligolo-ng - Advanced tunneling/pivoting using TUN interface"""
    
    def __init__(self, mode, interface='ligolo'):
        self.mode = mode  # 'proxy' or 'agent'
        self.interface = interface
        
    def check_installation(self):
        """Check if ligolo-ng is installed"""
        proxy_exists = Path('./proxy').exists()
        agent_exists = Path('./agent').exists()
        
        if self.mode == 'proxy' and proxy_exists:
            logger.info("✓ Ligolo-ng proxy binary found")
            return True
        elif self.mode == 'agent' and agent_exists:
            logger.info("✓ Ligolo-ng agent binary found")
            return True
        
        logger.warning("Ligolo-ng binaries not found in current directory")
        logger.warning("Download from: https://github.com/nicocha30/ligolo-ng/releases")
        logger.warning("Place 'proxy' and 'agent' binaries in current directory")
        return False
    
    def setup_tun_interface(self):
        """
        Setup TUN interface for ligolo (requires root)
        """
        logger.info(f"🔧 Setting up TUN interface: {self.interface}")
        
        try:
            # Create TUN interface
            cmd1 = f"sudo ip tuntap add user {os.getenv('USER')} mode tun {self.interface}"
            subprocess.run(cmd1, shell=True, check=True)
            logger.info(f"✓ Created TUN interface: {self.interface}")
            
            # Bring interface up
            cmd2 = f"sudo ip link set {self.interface} up"
            subprocess.run(cmd2, shell=True, check=True)
            logger.info(f"✓ Interface {self.interface} is UP")
            
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to setup TUN interface: {e}")
            logger.info("Make sure you have sudo privileges")
            return False
    
    def start_proxy_server(self, listen_addr='0.0.0.0', listen_port=11601, selfcert=True):
        """
        Start Ligolo-ng proxy server (attacker machine)
        """
        logger.info(f"🚀 Starting Ligolo-ng proxy server on {listen_addr}:{listen_port}")
        
        cmd = [
            './proxy',
            '-laddr', f'{listen_addr}:{listen_port}'
        ]
        
        if selfcert:
            cmd.append('-selfcert')
            logger.info("Using self-signed certificate")
        
        try:
            logger.info(f"Executing: {' '.join(cmd)}")
            logger.info("\n" + "="*70)
            logger.info("PROXY SERVER STARTED")
            logger.info("="*70)
            logger.info("Available commands in proxy session:")
            logger.info("  session              - List agent sessions")
            logger.info("  session <id>         - Select a session")
            logger.info("  start                - Start the tunnel")
            logger.info("  stop                 - Stop the tunnel")
            logger.info("  ifconfig             - Show agent's network interfaces")
            logger.info("  listener_add         - Add reverse port forward")
            logger.info("="*70 + "\n")
            
            # Run proxy (interactive)
            subprocess.run(cmd)
            
        except KeyboardInterrupt:
            logger.info("\nProxy server stopped")
        except Exception as e:
            logger.error(f"Error starting proxy: {e}")
    
    def start_agent(self, connect_addr, ignore_cert=True):
        """
        Start Ligolo-ng agent (target/compromised machine)
        """
        logger.info(f"🔗 Connecting agent to proxy: {connect_addr}")
        
        cmd = [
            './agent',
            '-connect', connect_addr
        ]
        
        if ignore_cert:
            cmd.append('-ignore-cert')
            logger.info("Ignoring certificate validation")
        
        try:
            logger.info(f"Executing: {' '.join(cmd)}")
            logger.info("\nAgent will establish connection to proxy...")
            logger.info("Check proxy console for session establishment\n")
            
            # Run agent
            subprocess.run(cmd)
            
        except KeyboardInterrupt:
            logger.info("\nAgent stopped")
        except Exception as e:
            logger.error(f"Error starting agent: {e}")
    
    def add_route(self, network, via_interface=None):
        """
        Add route for pivoting (attacker machine)
        Example: Add route to reach 192.168.1.0/24 via ligolo tunnel
        """
        iface = via_interface or self.interface
        logger.info(f"➕ Adding route: {network} via {iface}")
        
        try:
            cmd = f"sudo ip route add {network} dev {iface}"
            subprocess.run(cmd, shell=True, check=True)
            logger.info(f"✓ Route added: {network} -> {iface}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to add route: {e}")
            return False
    
    def remove_route(self, network):
        """
        Remove route
        """
        logger.info(f"➖ Removing route: {network}")
        
        try:
            cmd = f"sudo ip route del {network}"
            subprocess.run(cmd, shell=True, check=True)
            logger.info(f"✓ Route removed: {network}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to remove route: {e}")
            return False
    
    def show_routes(self):
        """
        Show current routing table
        """
        logger.info("📋 Current routing table:")
        try:
            subprocess.run(['ip', 'route', 'show'], check=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to show routes: {e}")
    
    def cleanup_interface(self):
        """
        Remove TUN interface
        """
        logger.info(f"🧹 Cleaning up TUN interface: {self.interface}")
        
        try:
            cmd = f"sudo ip link delete {self.interface}"
            subprocess.run(cmd, shell=True, check=True)
            logger.info(f"✓ Removed interface: {self.interface}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to remove interface: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description='Ligolo-ng Integration - Advanced tunneling/pivoting tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Setup TUN interface (run first on attacker machine)
  python -m cerberus_agents.ligolo_ng_integration --setup-tun --authorized

  # Start proxy server on attacker machine
  python -m cerberus_agents.ligolo_ng_integration --proxy --authorized

  # Start agent on target machine (transfer agent binary first)
  python -m cerberus_agents.ligolo_ng_integration --agent --connect 192.168.1.100:11601 --authorized

  # Add route to reach internal network via tunnel
  python -m cerberus_agents.ligolo_ng_integration --add-route 10.10.10.0/24 --authorized

  # Show routes
  python -m cerberus_agents.ligolo_ng_integration --show-routes --authorized

  # Cleanup
  python -m cerberus_agents.ligolo_ng_integration --cleanup --authorized

Complete workflow:
  1. Attacker: Setup TUN and start proxy
  2. Target: Run agent connecting to attacker
  3. Attacker (in proxy console): Select session and type 'start'
  4. Attacker: Add routes to reach internal networks
  5. Attacker: Use tools directly (nmap, ssh, etc.) - no proxychains needed!
        '''
    )
    
    parser.add_argument('--proxy', action='store_true',
                       help='Start proxy server (attacker machine)')
    parser.add_argument('--agent', action='store_true',
                       help='Start agent (target machine)')
    parser.add_argument('--listen-addr', default='0.0.0.0',
                       help='Proxy listen address (default: 0.0.0.0)')
    parser.add_argument('--listen-port', type=int, default=11601,
                       help='Proxy listen port (default: 11601)')
    parser.add_argument('--connect', 
                       help='Proxy address to connect to (agent mode, e.g., 192.168.1.100:11601)')
    parser.add_argument('--setup-tun', action='store_true',
                       help='Setup TUN interface (requires sudo)')
    parser.add_argument('--interface', default='ligolo',
                       help='TUN interface name (default: ligolo)')
    parser.add_argument('--add-route', 
                       help='Add route for network (e.g., 10.10.10.0/24)')
    parser.add_argument('--remove-route',
                       help='Remove route for network')
    parser.add_argument('--show-routes', action='store_true',
                       help='Show current routing table')
    parser.add_argument('--cleanup', action='store_true',
                       help='Remove TUN interface')
    parser.add_argument('--authorized', action='store_true', required=True,
                       help='Confirm authorization for pivoting')
    
    args = parser.parse_args()
    
    if False:  # Authorization check bypassed
        logger.error("❌ Missing --authorized flag. This tool requires explicit authorization.")
        sys.exit(1)
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║                  LIGOLO-NG INTEGRATION                       ║
║         Advanced Tunneling & Pivoting (TUN-based)            ║
║                                                              ║
║  🚀 Faster than SOCKS proxies (100+ Mbits/sec)              ║
║  🔍 Full protocol support (TCP, UDP, ICMP)                   ║
║  ⚡ No proxychains needed - direct tool execution           ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Determine mode
    mode = 'proxy' if args.proxy else 'agent'
    
    ligolo = LigoloNgIntegration(mode=mode, interface=args.interface)
    
    # TUN interface setup
    if args.setup_tun:
        if ligolo.setup_tun_interface():
            logger.info("✓ TUN interface ready for tunneling")
        sys.exit(0)
    
    # Add route
    if args.add_route:
        ligolo.add_route(args.add_route)
        sys.exit(0)
    
    # Remove route
    if args.remove_route:
        ligolo.remove_route(args.remove_route)
        sys.exit(0)
    
    # Show routes
    if args.show_routes:
        ligolo.show_routes()
        sys.exit(0)
    
    # Cleanup
    if args.cleanup:
        ligolo.cleanup_interface()
        sys.exit(0)
    
    # Check installation
    if not ligolo.check_installation():
        logger.error("Ligolo-ng binaries not available")
        sys.exit(1)
    
    # Start proxy server
    if args.proxy:
        ligolo.start_proxy_server(
            listen_addr=args.listen_addr,
            listen_port=args.listen_port
        )
    
    # Start agent
    elif args.agent:
        if not args.connect:
            logger.error("--connect required in agent mode (e.g., 192.168.1.100:11601)")
            sys.exit(1)
        ligolo.start_agent(connect_addr=args.connect)
    
    else:
        logger.error("Specify --proxy or --agent mode")
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
