#!/usr/bin/env python3
"""
reconFTW - Automated Reconnaissance Workflow
Complete automated recon combining subdomain enumeration with vulnerability scanning
Production-ready OSINT and web reconnaissance
"""

import subprocess
import os
import logging
from pathlib import Path
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ReconFTWAutomation:
    """reconFTW automated reconnaissance workflow"""
    
    def __init__(self):
        self.reconftw_path = str(Path.home() / "reconftw")
    
    def check_installation(self) -> Dict[str, any]:
        """Check reconFTW installation"""
        result = {
            "installed": False,
            "path": None,
            "install_commands": [
                "git clone https://github.com/six2dez/reconftw ~/reconftw",
                "cd ~/reconftw",
                "./install.sh",
                "# Configure API keys in ~/.config/reconftw/reconftw.cfg"
            ]
        }
        
        reconftw_script = Path(self.reconftw_path) / "reconftw.sh"
        if reconftw_script.exists():
            result["installed"] = True
            result["path"] = str(reconftw_script)
        
        return result
    
    def run_recon(self, target: str, mode: str = "full", output_dir: str = None) -> Dict[str, any]:
        """
        Run automated reconnaissance
        
        Args:
            target: Domain to recon
            mode: full, basic, passive, subdomain, web
            output_dir: Custom output directory
        """
        if not Path(self.reconftw_path).exists():
            return {"error": "reconFTW not installed"}
        
        cmd = [
            f"{self.reconftw_path}/reconftw.sh",
            "-d", target
        ]
        
        mode_map = {
            "full": "-r",
            "basic": "-a",
            "passive": "-p",
            "subdomain": "-s",
            "web": "-w"
        }
        
        if mode in mode_map:
            cmd.append(mode_map[mode])
        
        if output_dir:
            cmd.extend(["-o", output_dir])
        
        try:
            logger.info(f"Running reconFTW: {' '.join(cmd)}")
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            return {
                "success": True,
                "target": target,
                "mode": mode,
                "pid": process.pid,
                "message": "Recon started in background"
            }
        except Exception as e:
            return {"error": str(e)}
    
    def get_info(self) -> Dict[str, any]:
        """Get reconFTW information"""
        return {
            "name": "reconFTW",
            "description": "Automated reconnaissance workflow",
            "features": [
                "Subdomain enumeration (Amass, Subfinder, Assetfinder)",
                "DNS resolution and probing",
                "Port scanning (Nmap, Masscan)",
                "Web screenshot (Gowitness)",
                "Vulnerability scanning (Nuclei)",
                "JavaScript analysis",
                "Parameter discovery",
                "URL fuzzing",
                "Technology detection",
                "GitHub dorking"
            ],
            "scan_modes": {
                "full": "Complete recon (subdomain + web + vuln scan)",
                "basic": "Quick scan with essential tools",
                "passive": "Passive OSINT only",
                "subdomain": "Subdomain enumeration only",
                "web": "Web-focused reconnaissance"
            },
            "integrated_tools": [
                "Amass", "Subfinder", "Assetfinder", "Findomain",
                "Nuclei", "Nmap", "Masscan", "httprobe",
                "Gowitness", "Waybackurls", "gf", "ffuf",
                "Sublist3r", "Shodan", "GitHub-subdomains"
            ],
            "output": "HTML reports with screenshots and findings",
            "github": "https://github.com/six2dez/reconftw"
        }


def main():
    """CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description="reconFTW Automation")
    parser.add_argument("--check", action="store_true", help="Check installation")
    parser.add_argument("--info", action="store_true", help="Show tool info")
    parser.add_argument("--target", help="Target domain")
    parser.add_argument("--mode", default="full", 
                       choices=["full", "basic", "passive", "subdomain", "web"])
    parser.add_argument("--output", help="Output directory")
    
        parser.add_argument('--authorized', action='store_true',
                       help='Confirm you have authorization to perform this action')
    args = parser.parse_args()
    
    recon = ReconFTWAutomation()
    
    if args.check:
        status = recon.check_installation()
        print("\n═══ reconFTW Installation Status ═══")
        print(f"Installed: {status['installed']}")
        if status['installed']:
            print(f"Path: {status['path']}")
        else:
            print(f"\n📥 Installation Commands:")
            for cmd in status['install_commands']:
                print(f"   {cmd}")
    
    elif args.info:
        info = recon.get_info()
        print("\n═══ reconFTW Automated Reconnaissance ═══")
        print(f"Name: {info['name']}")
        print(f"Description: {info['description']}")
        print(f"\n🎯 Features:")
        for feature in info['features']:
            print(f"   • {feature}")
        print(f"\n📊 Scan Modes:")
        for mode, desc in info['scan_modes'].items():
            print(f"   • {mode}: {desc}")
        print(f"\n🔗 GitHub: {info['github']}")
    
    elif args.target:
        print(f"\n🔍 Starting {args.mode} reconnaissance on {args.target}...")
        result = recon.run_recon(args.target, args.mode, args.output)
        if "success" in result:
            print(f"✅ Recon started! PID: {result['pid']}")
            print(f"   Mode: {result['mode']}")
        else:
            print(f"❌ Error: {result.get('error')}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
