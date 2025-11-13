#!/usr/bin/env python3
"""
Wifite2 Integration - Automated WiFi Auditing
Fully automated wireless security assessment
WPA/WPA2/WPS/WEP cracking with minimal user interaction
"""

import subprocess
import logging
import os
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class Wifite2Automation:
    """
    Wifite2 Integration
    Automated wireless auditing tool
    """
    
    def __init__(self):
        self.wifite_path = self._find_wifite()
        
    def _find_wifite(self) -> Optional[str]:
        """Locate wifite binary"""
        result = subprocess.run(["which", "wifite"], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
        return None
    
    def install_wifite(self) -> Dict[str, any]:
        """Install Wifite2 and dependencies"""
        logger.info("Installing Wifite2...")
        
        try:
            commands = [
                "sudo apt install -y wifite",
                "sudo apt install -y aircrack-ng reaver bully hashcat hcxtools hcxdumptool"
            ]
            
            for cmd in commands:
                result = subprocess.run(
                    cmd.split(),
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                
                if result.returncode != 0:
                    return {"success": False, "error": result.stderr}
            
            self.wifite_path = "/usr/bin/wifite"
            
            return {
                "success": True,
                "message": "Wifite2 and dependencies installed successfully"
            }
                
        except Exception as e:
            logger.error(f"Installation failed: {e}")
            return {"success": False, "error": str(e)}
    
    def scan_and_attack(self, interface: str = "wlan0", attack_types: List[str] = None,
                        power_threshold: int = 50, max_time: int = 300) -> Dict[str, any]:
        """
        Run automated WiFi attack
        
        Args:
            interface: Wireless interface
            attack_types: ['wps', 'wpa', 'wep', 'pmkid'] or None for all
            power_threshold: Minimum signal power (dB)
            max_time: Maximum runtime per attack (seconds)
        """
        if not self.wifite_path:
            return {"success": False, "error": "Wifite not installed"}
        
        logger.info(f"Starting automated WiFi attack on {interface}")
        
        try:
            cmd = ["sudo", self.wifite_path, "-i", interface, "--pow", str(power_threshold)]
            
            if attack_types:
                if "wps" in attack_types:
                    cmd.append("--wps")
                if "wpa" in attack_types:
                    cmd.append("--wpa")
                if "wep" in attack_types:
                    cmd.append("--wep")
                if "pmkid" in attack_types:
                    cmd.append("--pmkid")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            return {
                "success": True,
                "message": f"Automated attack started on {interface}",
                "pid": process.pid,
                "attacks": attack_types or ["all"],
                "power_threshold": power_threshold
            }
            
        except Exception as e:
            logger.error(f"Attack failed: {e}")
            return {"success": False, "error": str(e)}
    
    def wps_attack(self, interface: str = "wlan0", pixie_dust: bool = True) -> Dict[str, any]:
        """
        WPS-only attack
        
        Args:
            interface: Wireless interface
            pixie_dust: Use Pixie-Dust attack
        """
        logger.info("Starting WPS attack")
        
        try:
            cmd = ["sudo", self.wifite_path, "-i", interface, "--wps"]
            
            if pixie_dust:
                cmd.append("--wps-pixie")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            return {
                "success": True,
                "message": "WPS attack started",
                "pid": process.pid,
                "pixie_dust": pixie_dust
            }
            
        except Exception as e:
            logger.error(f"WPS attack failed: {e}")
            return {"success": False, "error": str(e)}
    
    def pmkid_attack(self, interface: str = "wlan0", 
                     wordlist: str = "/usr/share/wordlists/rockyou.txt") -> Dict[str, any]:
        """
        PMKID attack (clientless WPA/WPA2)
        
        Args:
            interface: Wireless interface
            wordlist: Password wordlist
        """
        logger.info("Starting PMKID attack")
        
        try:
            cmd = [
                "sudo", self.wifite_path,
                "-i", interface,
                "--pmkid",
                "--dict", wordlist
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            return {
                "success": True,
                "message": "PMKID attack started (no clients needed)",
                "pid": process.pid,
                "wordlist": wordlist
            }
            
        except Exception as e:
            logger.error(f"PMKID attack failed: {e}")
            return {"success": False, "error": str(e)}
    
    def target_specific(self, bssid: str, interface: str = "wlan0",
                        wordlist: Optional[str] = None) -> Dict[str, any]:
        """
        Target specific network
        
        Args:
            bssid: Target BSSID
            interface: Wireless interface
            wordlist: Custom wordlist
        """
        logger.info(f"Targeting specific network: {bssid}")
        
        try:
            cmd = [
                "sudo", self.wifite_path,
                "-i", interface,
                "-b", bssid
            ]
            
            if wordlist:
                cmd.extend(["--dict", wordlist])
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            return {
                "success": True,
                "message": f"Targeting {bssid}",
                "pid": process.pid,
                "bssid": bssid
            }
            
        except Exception as e:
            logger.error(f"Targeted attack failed: {e}")
            return {"success": False, "error": str(e)}
    
    def crack_with_custom_wordlist(self, wordlist_path: str, 
                                    interface: str = "wlan0") -> Dict[str, any]:
        """
        Use custom wordlist for cracking
        
        Args:
            wordlist_path: Path to custom wordlist
            interface: Wireless interface
        """
        if not os.path.exists(wordlist_path):
            return {"success": False, "error": f"Wordlist not found: {wordlist_path}"}
        
        logger.info(f"Using custom wordlist: {wordlist_path}")
        
        try:
            cmd = [
                "sudo", self.wifite_path,
                "-i", interface,
                "--dict", wordlist_path,
                "--wpa"
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            return {
                "success": True,
                "message": f"Attack started with custom wordlist",
                "pid": process.pid,
                "wordlist": wordlist_path
            }
            
        except Exception as e:
            logger.error(f"Custom wordlist attack failed: {e}")
            return {"success": False, "error": str(e)}


def demonstrate_wifite():
    """Demonstrate Wifite2 capabilities"""
    print("\n" + "="*70)
    print("WIFITE2 - AUTOMATED WIFI AUDITING")
    print("="*70)
    
    wifite = Wifite2Automation()
    
    print("\n[*] Production Features:")
    print("    ✓ Fully automated WiFi auditing")
    print("    ✓ WPS Pixie-Dust attacks")
    print("    ✓ WPS PIN bruteforce (Reaver/Bully)")
    print("    ✓ WPA/WPA2 handshake capture")
    print("    ✓ PMKID attacks (clientless)")
    print("    ✓ WEP cracking")
    print("    ✓ Automatic wordlist cracking")
    print("    ✓ Smart filtering by power/channel/encryption")
    
    print("\n[*] Attack Methods:")
    print("    • WPS: Pixie-Dust + PIN bruteforce")
    print("    • PMKID: Clientless WPA/WPA2 (via hcxtools)")
    print("    • WPA: Handshake capture + dictionary")
    print("    • WEP: Statistical attacks")
    
    print("\n[*] Usage Examples:")
    print("    Auto attack: wifite.scan_and_attack('wlan0')")
    print("    WPS only: wifite.wps_attack('wlan0')")
    print("    PMKID: wifite.pmkid_attack('wlan0')")
    print("    Targeted: wifite.target_specific('AA:BB:CC:DD:EE:FF')")
    
    print("\n[*] Advantages:")
    print("    ✓ No manual intervention needed")
    print("    ✓ Automatically tries all attack vectors")
    print("    ✓ Detects WPS-locked networks")
    print("    ✓ Integrates with hashcat for GPU cracking")
    
    print("\n[!] Authorization Required: WiFi attacks require explicit permission")
    print("="*70)


if __name__ == "__main__":
    demonstrate_wifite()
