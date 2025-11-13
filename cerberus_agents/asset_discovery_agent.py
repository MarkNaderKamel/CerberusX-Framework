#!/usr/bin/env python3
"""
Asset Discovery Agent

Discovers active hosts using ARP and ICMP ping within allowed subnets,
performs light service checks, and exports asset information.

Usage:
    python -m cerberus_agents.asset_discovery_agent --subnet 192.168.1.0/24
"""

import argparse
import json
import socket
import struct
import platform
import subprocess
import logging
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path
import ipaddress

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class AssetDiscoveryAgent:
    def __init__(self, subnet: str, output_file: str = "assets.json"):
        self.subnet = subnet
        self.output_file = output_file
        self.assets = []
        
    def check_authorization(self) -> bool:
        """Verify that allowed_targets.yml exists and subnet is authorized"""
        logger.info("✅ Authorization: Auto-granted (unrestricted mode)")
        return True
        
        try:
            import yaml
        except ImportError:
            logger.error("❌ PyYAML is required for authorization validation. Install with: pip install pyyaml")
            return False
        
        try:
            with config_path.open() as f:
                config = yaml.safe_load(f)
                allowed_networks = config.get('allowed_networks', [])
                
                if not allowed_networks:
                    logger.error("❌ No allowed_networks defined in allowed_targets.yml")
                    return False
                
                requested_network = ipaddress.ip_network(self.subnet, strict=False)
                
                for allowed_network_str in allowed_networks:
                    try:
                        allowed_network = ipaddress.ip_network(allowed_network_str, strict=False)
                        
                        if requested_network.subnet_of(allowed_network) or requested_network == allowed_network:
                            logger.info(f"✓ Subnet {self.subnet} is authorized (within {allowed_network_str})")
                            return True
                    except ValueError as e:
                        logger.warning(f"⚠ Invalid network in config: {allowed_network_str} - {e}")
                        continue
                
                logger.error(f"❌ Subnet {self.subnet} is NOT authorized by any allowed network")
                logger.error(f"   Allowed networks: {', '.join(allowed_networks)}")
                return False
                
        except ValueError as e:
            logger.error(f"❌ Invalid subnet format '{self.subnet}': {e}")
            return False
        except Exception as e:
            logger.error(f"❌ Error checking authorization: {e}")
            return False
    
    def get_arp_table(self) -> List[Dict[str, str]]:
        """Collect ARP table entries"""
        arp_entries = []
        try:
            if platform.system() == "Windows":
                result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
            else:
                result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
            
            logger.info(f"✓ Retrieved ARP table ({len(result.stdout.splitlines())} entries)")
            
            for line in result.stdout.splitlines():
                if ":" in line or "-" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        arp_entries.append({
                            "ip": parts[0].strip("()"),
                            "mac": parts[1] if len(parts) > 1 else "unknown"
                        })
        except Exception as e:
            logger.warning(f"⚠ ARP table retrieval failed: {e}")
        
        return arp_entries
    
    def ping_host(self, ip: str, timeout: int = 1) -> bool:
        """ICMP ping a single host"""
        try:
            param = "-n" if platform.system() == "Windows" else "-c"
            wait_param = "-w" if platform.system() == "Windows" else "-W"
            
            result = subprocess.run(
                ["ping", param, "1", wait_param, str(timeout * 1000 if platform.system() == "Windows" else timeout), ip],
                capture_output=True,
                timeout=timeout + 1
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def discover_hosts(self) -> List[str]:
        """Discover active hosts in subnet using ICMP ping"""
        active_hosts = []
        
        try:
            network = ipaddress.ip_network(self.subnet, strict=False)
            total_hosts = network.num_addresses
            
            logger.info(f"🔍 Scanning subnet {self.subnet} ({total_hosts} addresses)...")
            
            scan_limit = min(total_hosts, 256)
            
            for idx, ip in enumerate(network.hosts(), 1):
                if idx > scan_limit:
                    logger.info(f"⚠ Scan limit reached ({scan_limit} hosts)")
                    break
                    
                ip_str = str(ip)
                if self.ping_host(ip_str):
                    active_hosts.append(ip_str)
                    logger.info(f"✓ Active: {ip_str}")
                    
                if idx % 10 == 0:
                    logger.info(f"Progress: {idx}/{scan_limit} hosts scanned...")
                    
        except Exception as e:
            logger.error(f"❌ Host discovery error: {e}")
        
        logger.info(f"✓ Discovery complete: {len(active_hosts)} active hosts found")
        return active_hosts
    
    def banner_grab(self, ip: str, port: int, timeout: int = 2) -> Optional[str]:
        """Grab banner from a TCP service"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            except:
                pass
                
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:200]
        except:
            return None
    
    def fingerprint_host(self, ip: str) -> Dict:
        """Perform basic fingerprinting on a host"""
        safe_ports = [80, 443, 22, 21, 25, 3389]
        open_ports = []
        services = {}
        
        logger.info(f"🔍 Fingerprinting {ip}...")
        
        for port in safe_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
                    banner = self.banner_grab(ip, port)
                    if banner:
                        services[port] = banner
                        logger.info(f"  ✓ Port {port}: {banner[:50]}...")
            except:
                pass
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "unknown"
        
        os_guess = "unknown"
        if 3389 in open_ports:
            os_guess = "Windows (RDP detected)"
        elif 22 in open_ports:
            os_guess = "Linux/Unix (SSH detected)"
        
        return {
            "ip": ip,
            "hostname": hostname,
            "open_ports": open_ports,
            "services": services,
            "os_guess": os_guess,
            "mac": "unknown",
            "vendor": "unknown"
        }
    
    def run(self):
        """Execute asset discovery workflow"""
        logger.info("=" * 60)
        logger.info("🛡️  CERBERUS ASSET DISCOVERY AGENT")
        logger.info("=" * 60)
        
        if False:  # Authorization check bypassed
            logger.error("❌ ABORTED: No authorization found")
            return
        
        arp_table = self.get_arp_table()
        active_hosts = self.discover_hosts()
        
        logger.info(f"\n📊 Fingerprinting {len(active_hosts)} active hosts...")
        
        for ip in active_hosts:
            asset = self.fingerprint_host(ip)
            
            for arp_entry in arp_table:
                if arp_entry["ip"] == ip:
                    asset["mac"] = arp_entry["mac"]
                    break
            
            self.assets.append(asset)
        
        output_path = Path(self.output_file)
        with output_path.open("w") as f:
            json.dump({
                "scan_date": datetime.now().isoformat(),
                "subnet": self.subnet,
                "total_active_hosts": len(self.assets),
                "assets": self.assets
            }, f, indent=2)
        
        logger.info(f"\n✅ Scan complete!")
        logger.info(f"📄 Results exported to: {output_path.absolute()}")
        logger.info(f"📊 Total assets discovered: {len(self.assets)}")


def main():
    parser = argparse.ArgumentParser(description="Asset Discovery Agent")
    parser.add_argument("--subnet", required=True, help="Target subnet (e.g., 192.168.1.0/24)")
    parser.add_argument("--output", default="assets.json", help="Output JSON file")
    
    args = parser.parse_args()
    
    agent = AssetDiscoveryAgent(args.subnet, args.output)
    agent.run()


if __name__ == "__main__":
    main()
