#!/usr/bin/env python3
"""
SpiderFoot OSINT Automation Platform
Automated reconnaissance and intelligence gathering
Production-ready OSINT framework with 200+ modules
"""

import subprocess
import requests
import json
import logging
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SpiderFootOSINT:
    """SpiderFoot OSINT automation platform integration"""
    
    def __init__(self, api_url: str = "http://127.0.0.1:5001", api_key: str = None):
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.headers = {"Content-Type": "application/json"}
        if api_key:
            self.headers["Authorization"] = f"Bearer {api_key}"
    
    def check_installation(self) -> Dict[str, any]:
        """Check SpiderFoot installation"""
        result = {
            "installed": False,
            "running": False,
            "install_commands": [
                "wget https://github.com/smicallef/spiderfoot/archive/master.zip",
                "unzip master.zip && cd spiderfoot-master",
                "pip3 install -r requirements.txt",
                "python3 ./sf.py -l 127.0.0.1:5001"
            ]
        }
        
        try:
            response = requests.get(f"{self.api_url}/api", timeout=5)
            if response.status_code == 200:
                result["installed"] = True
                result["running"] = True
        except Exception as e:
            logger.warning(f"SpiderFoot not running: {e}")
        
        return result
    
    def start_scan(self, target: str, scan_name: str = None, 
                   modules: List[str] = None, scan_type: str = "all") -> Dict[str, any]:
        """
        Start OSINT scan
        
        Args:
            target: Domain, IP, email, or company name
            scan_name: Custom scan name
            modules: Specific modules to use (default: all)
            scan_type: all, passive, or footprint
        """
        scan_name = scan_name or f"scan_{target}"
        
        payload = {
            "scanname": scan_name,
            "scantarget": target,
            "usecase": scan_type,
            "modulelist": modules or []
        }
        
        try:
            response = requests.post(
                f"{self.api_url}/api/startscan",
                headers=self.headers,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "success": True,
                    "scan_id": data.get("id"),
                    "scan_name": scan_name,
                    "target": target
                }
            return {"error": f"API returned {response.status_code}: {response.text}"}
        except Exception as e:
            return {"error": str(e)}
    
    def get_scan_status(self, scan_id: str) -> Dict[str, any]:
        """Get scan status"""
        try:
            response = requests.get(
                f"{self.api_url}/api/scanstatus/{scan_id}",
                headers=self.headers,
                timeout=10
            )
            return response.json() if response.status_code == 200 else {"error": "Not found"}
        except Exception as e:
            return {"error": str(e)}
    
    def get_scan_results(self, scan_id: str) -> List[Dict[str, any]]:
        """Get scan results"""
        try:
            response = requests.get(
                f"{self.api_url}/api/scanresults/{scan_id}",
                headers=self.headers,
                timeout=30
            )
            return response.json() if response.status_code == 200 else []
        except Exception as e:
            logger.error(f"Failed to get results: {e}")
            return []
    
    def list_scans(self) -> List[Dict[str, any]]:
        """List all scans"""
        try:
            response = requests.get(
                f"{self.api_url}/api/scans",
                headers=self.headers,
                timeout=10
            )
            return response.json() if response.status_code == 200 else []
        except Exception as e:
            return []
    
    def list_modules(self) -> List[Dict[str, any]]:
        """List available OSINT modules"""
        try:
            response = requests.get(
                f"{self.api_url}/api/modules",
                headers=self.headers,
                timeout=10
            )
            return response.json() if response.status_code == 200 else []
        except Exception as e:
            return []
    
    def stop_scan(self, scan_id: str) -> Dict[str, any]:
        """Stop running scan"""
        try:
            response = requests.get(
                f"{self.api_url}/api/stopscan/{scan_id}",
                headers=self.headers,
                timeout=10
            )
            return {"success": response.status_code == 200}
        except Exception as e:
            return {"error": str(e)}
    
    def get_info(self) -> Dict[str, any]:
        """Get SpiderFoot information"""
        return {
            "name": "SpiderFoot OSINT Platform",
            "description": "Automated reconnaissance and intelligence gathering",
            "features": [
                "200+ OSINT modules",
                "Web-based UI + REST API",
                "Automated data correlation",
                "Real-time scanning",
                "Export to CSV/JSON/GEXF",
                "Passive and active reconnaissance",
                "Integration with 3rd-party APIs"
            ],
            "module_categories": [
                "DNS Resolution",
                "Email Harvesting",
                "IP/ASN Enumeration",
                "SSL Certificate Analysis",
                "WHOIS Lookups",
                "Search Engine Queries",
                "Social Media Discovery",
                "Dark Web Monitoring",
                "Data Breach Checking",
                "Company Information",
                "Phone Number OSINT",
                "Domain Relationships"
            ],
            "data_sources": [
                "Shodan", "Censys", "VirusTotal", "AlienVault OTX",
                "GitHub", "PasteBin", "HaveIBeenPwned", "Hunter.io",
                "Security Trails", "BGPView", "BuiltWith", "DNSDumpster"
            ],
            "use_cases": [
                "External attack surface mapping",
                "Digital footprint analysis",
                "Brand monitoring",
                "Threat intelligence",
                "Pre-engagement reconnaissance",
                "Supply chain security"
            ],
            "github": "https://github.com/smicallef/spiderfoot",
            "default_port": 5001
        }


def main():
    """CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description="SpiderFoot OSINT Platform")
    parser.add_argument("--check", action="store_true", help="Check installation")
    parser.add_argument("--info", action="store_true", help="Show platform info")
    parser.add_argument("--api-url", default="http://127.0.0.1:5001", help="SpiderFoot API URL")
    parser.add_argument("--scan", help="Start scan on target")
    parser.add_argument("--scan-name", help="Custom scan name")
    parser.add_argument("--scan-type", default="all", choices=["all", "passive", "footprint"])
    parser.add_argument("--status", help="Get scan status by ID")
    parser.add_argument("--results", help="Get scan results by ID")
    parser.add_argument("--list-scans", action="store_true", help="List all scans")
    parser.add_argument("--list-modules", action="store_true", help="List all modules")
    
        parser.add_argument('--authorized', action='store_true',
                       help='Confirm you have authorization to perform this action')
    args = parser.parse_args()
    
    sf = SpiderFootOSINT(api_url=args.api_url)
    
    if args.check:
        status = sf.check_installation()
        print("\n═══ SpiderFoot Installation Status ═══")
        print(f"Installed: {status['installed']}")
        print(f"Running: {status['running']}")
        if not status['running']:
            print(f"\n📥 Installation Commands:")
            for cmd in status['install_commands']:
                print(f"   {cmd}")
    
    elif args.info:
        info = sf.get_info()
        print("\n═══ SpiderFoot OSINT Platform ═══")
        print(f"Name: {info['name']}")
        print(f"Description: {info['description']}")
        print(f"\n🎯 Features:")
        for feature in info['features']:
            print(f"   • {feature}")
        print(f"\n📊 Module Categories:")
        for category in info['module_categories']:
            print(f"   • {category}")
        print(f"\n🔗 Data Sources: {len(info['data_sources'])} integrated")
        print(f"🔗 GitHub: {info['github']}")
    
    elif args.scan:
        print(f"\n🔍 Starting OSINT scan on {args.scan}...")
        result = sf.start_scan(args.scan, args.scan_name, scan_type=args.scan_type)
        if "success" in result:
            print(f"✅ Scan started!")
            print(f"   Scan ID: {result['scan_id']}")
            print(f"   Target: {result['target']}")
        else:
            print(f"❌ Error: {result.get('error')}")
    
    elif args.status:
        status = sf.get_scan_status(args.status)
        print(f"\n📊 Scan Status:")
        print(json.dumps(status, indent=2))
    
    elif args.results:
        results = sf.get_scan_results(args.results)
        print(f"\n📋 Scan Results: {len(results)} items found")
        for result in results[:10]:
            print(f"   • {result}")
    
    elif args.list_scans:
        scans = sf.list_scans()
        print(f"\n📝 Active Scans: {len(scans)}")
        for scan in scans:
            print(f"   ID: {scan.get('id')} - {scan.get('name')}")
    
    elif args.list_modules:
        modules = sf.list_modules()
        print(f"\n🧩 Available Modules: {len(modules)}")
        for module in modules[:20]:
            print(f"   • {module.get('name', 'Unknown')}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
