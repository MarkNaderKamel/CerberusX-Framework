#!/usr/bin/env python3
"""
OWASP ZAP (Zed Attack Proxy) Integration
Industry-standard web application security scanner
Automated and manual vulnerability testing
"""

import subprocess
import requests
import time
import logging
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class OWASPZAPScanner:
    """OWASP ZAP automated vulnerability scanner integration"""
    
    def __init__(self, api_url: str = "http://127.0.0.1:8080", api_key: str = None):
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
    
    def check_installation(self) -> Dict[str, any]:
        """Check ZAP installation"""
        result = {
            "installed": False,
            "running": False,
            "install_commands": [
                "# Download from https://www.zaproxy.org/download/",
                "# Or via package manager:",
                "snap install zaproxy --classic",
                "# Or Docker:",
                "docker pull ghcr.io/zaproxy/zaproxy:stable"
            ]
        }
        
        try:
            response = requests.get(f"{self.api_url}/JSON/core/view/version/", timeout=5)
            if response.status_code == 200:
                result["installed"] = True
                result["running"] = True
                result["version"] = response.json().get("version")
        except Exception:
            pass
        
        return result
    
    def spider_scan(self, target_url: str, max_depth: int = 5) -> Dict[str, any]:
        """
        Spider/crawl target website
        
        Args:
            target_url: Target URL to spider
            max_depth: Maximum crawl depth
        """
        try:
            params = {
                "url": target_url,
                "maxChildren": max_depth
            }
            if self.api_key:
                params["apikey"] = self.api_key
            
            response = requests.get(
                f"{self.api_url}/JSON/spider/action/scan/",
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                scan_id = response.json().get("scan")
                return {
                    "success": True,
                    "scan_id": scan_id,
                    "target": target_url,
                    "type": "spider"
                }
            return {"error": f"Spider failed: {response.text}"}
        except Exception as e:
            return {"error": str(e)}
    
    def active_scan(self, target_url: str, spider_first: bool = True) -> Dict[str, any]:
        """
        Active vulnerability scan
        
        Args:
            target_url: Target URL
            spider_first: Run spider before active scan
        """
        if spider_first:
            spider_result = self.spider_scan(target_url)
            if "error" in spider_result:
                return spider_result
            time.sleep(5)
        
        try:
            params = {"url": target_url}
            if self.api_key:
                params["apikey"] = self.api_key
            
            response = requests.get(
                f"{self.api_url}/JSON/ascan/action/scan/",
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                scan_id = response.json().get("scan")
                return {
                    "success": True,
                    "scan_id": scan_id,
                    "target": target_url,
                    "type": "active"
                }
            return {"error": f"Active scan failed: {response.text}"}
        except Exception as e:
            return {"error": str(e)}
    
    def get_alerts(self, target_url: str = None, risk_level: str = None) -> List[Dict[str, any]]:
        """
        Get vulnerability alerts
        
        Args:
            target_url: Filter by URL
            risk_level: High, Medium, Low, Informational
        """
        try:
            params = {}
            if target_url:
                params["baseurl"] = target_url
            if self.api_key:
                params["apikey"] = self.api_key
            
            response = requests.get(
                f"{self.api_url}/JSON/core/view/alerts/",
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                alerts = response.json().get("alerts", [])
                
                if risk_level:
                    alerts = [a for a in alerts if a.get("risk", "").lower() == risk_level.lower()]
                
                return alerts
            return []
        except Exception as e:
            logger.error(f"Failed to get alerts: {e}")
            return []
    
    def baseline_scan(self, target_url: str) -> Dict[str, any]:
        """Quick baseline scan (spider + passive scan)"""
        try:
            spider_result = self.spider_scan(target_url)
            if "error" in spider_result:
                return spider_result
            
            time.sleep(10)
            
            alerts = self.get_alerts(target_url)
            high_risk = [a for a in alerts if a.get("risk") == "High"]
            medium_risk = [a for a in alerts if a.get("risk") == "Medium"]
            
            return {
                "success": True,
                "target": target_url,
                "total_alerts": len(alerts),
                "high_risk": len(high_risk),
                "medium_risk": len(medium_risk),
                "alerts": alerts
            }
        except Exception as e:
            return {"error": str(e)}
    
    def api_scan(self, api_definition_url: str, api_format: str = "openapi") -> Dict[str, any]:
        """
        Scan API from OpenAPI/Swagger definition
        
        Args:
            api_definition_url: URL or file path to API definition
            api_format: openapi, soap, graphql
        """
        try:
            params = {
                "file": api_definition_url,
                "target": api_definition_url
            }
            if self.api_key:
                params["apikey"] = self.api_key
            
            response = requests.get(
                f"{self.api_url}/JSON/{api_format}/action/importUrl/",
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                return {"success": True, "api_format": api_format}
            return {"error": f"API scan failed: {response.text}"}
        except Exception as e:
            return {"error": str(e)}
    
    def generate_report(self, target_url: str = None, report_format: str = "html",
                       output_file: str = "zap_report.html") -> Dict[str, any]:
        """
        Generate scan report
        
        Args:
            target_url: Filter by target
            report_format: html, xml, json, md
            output_file: Output file path
        """
        try:
            params = {}
            if target_url:
                params["baseurl"] = target_url
            if self.api_key:
                params["apikey"] = self.api_key
            
            endpoint_map = {
                "html": "/OTHER/core/other/htmlreport/",
                "xml": "/OTHER/core/other/xmlreport/",
                "json": "/JSON/core/view/alerts/",
                "md": "/OTHER/core/other/mdreport/"
            }
            
            response = requests.get(
                f"{self.api_url}{endpoint_map.get(report_format, endpoint_map['html'])}",
                params=params,
                timeout=60
            )
            
            if response.status_code == 200:
                with open(output_file, 'w') as f:
                    if report_format == "json":
                        f.write(response.json())
                    else:
                        f.write(response.text)
                
                return {
                    "success": True,
                    "format": report_format,
                    "output": output_file
                }
            return {"error": f"Report generation failed: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def get_info(self) -> Dict[str, any]:
        """Get OWASP ZAP information"""
        return {
            "name": "OWASP ZAP (Zed Attack Proxy)",
            "description": "Industry-standard web application security scanner",
            "features": [
                "Automated and manual security testing",
                "Intercepting proxy",
                "Active and passive scanning",
                "API testing (REST/SOAP/GraphQL)",
                "OpenAPI/Swagger support",
                "Spider/crawler",
                "Fuzzing capabilities",
                "WebSocket support",
                "AJAX spidering",
                "Extensive plugin ecosystem"
            ],
            "scan_types": {
                "Spider": "Crawl and discover URLs",
                "Passive Scan": "Analyze traffic passively",
                "Active Scan": "Actively test for vulnerabilities",
                "API Scan": "Test APIs via definitions",
                "Baseline": "Quick security assessment"
            },
            "detects": [
                "SQL Injection",
                "Cross-Site Scripting (XSS)",
                "Cross-Site Request Forgery (CSRF)",
                "XXE (XML External Entity)",
                "Security header issues",
                "Cookie security problems",
                "Directory traversal",
                "Remote code execution",
                "Authentication bypass",
                "Session management flaws"
            ],
            "output_formats": ["HTML", "XML", "JSON", "Markdown"],
            "integration": ["CI/CD", "Docker", "Jenkins", "GitLab CI", "GitHub Actions"],
            "website": "https://www.zaproxy.org",
            "github": "https://github.com/zaproxy/zaproxy",
            "default_port": 8080
        }


def main():
    """CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description="OWASP ZAP Scanner Integration")
    parser.add_argument("--check", action="store_true", help="Check installation")
    parser.add_argument("--info", action="store_true", help="Show scanner info")
    parser.add_argument("--api-url", default="http://127.0.0.1:8080", help="ZAP API URL")
    parser.add_argument("--api-key", help="ZAP API key")
    parser.add_argument("--target", help="Target URL to scan")
    parser.add_argument("--baseline", action="store_true", help="Quick baseline scan")
    parser.add_argument("--spider", action="store_true", help="Spider/crawl only")
    parser.add_argument("--active-scan", action="store_true", help="Active vulnerability scan")
    parser.add_argument("--alerts", action="store_true", help="Get vulnerability alerts")
    parser.add_argument("--risk-level", choices=["High", "Medium", "Low", "Informational"])
    parser.add_argument("--report", choices=["html", "xml", "json", "md"], help="Generate report")
    parser.add_argument("--output", default="zap_report.html", help="Report output file")
    parser.add_argument('--authorized', action='store_true',
                       help='Confirm you have authorization to perform this action')
    args = parser.parse_args()
    
    zap = OWASPZAPScanner(api_url=args.api_url, api_key=args.api_key)
    
    if args.check:
        status = zap.check_installation()
        print("\n═══ OWASP ZAP Installation Status ═══")
        print(f"Installed: {status['installed']}")
        print(f"Running: {status['running']}")
        if status.get('version'):
            print(f"Version: {status['version']}")
        if not status['running']:
            print(f"\n📥 Installation Options:")
            for cmd in status['install_commands']:
                print(f"   {cmd}")
    
    elif args.info:
        info = zap.get_info()
        print("\n═══ OWASP ZAP Scanner ═══")
        print(f"Name: {info['name']}")
        print(f"Description: {info['description']}")
        print(f"\n🎯 Features:")
        for feature in info['features']:
            print(f"   • {feature}")
        print(f"\n🐛 Detects:")
        for vuln in info['detects']:
            print(f"   • {vuln}")
        print(f"\n🔗 Website: {info['website']}")
    
    elif args.baseline and args.target:
        print(f"\n🚀 Running baseline scan on {args.target}...")
        result = zap.baseline_scan(args.target)
        if "success" in result:
            print(f"✅ Scan complete!")
            print(f"   Total Alerts: {result['total_alerts']}")
            print(f"   High Risk: {result['high_risk']}")
            print(f"   Medium Risk: {result['medium_risk']}")
        else:
            print(f"❌ Error: {result.get('error')}")
    
    elif args.spider and args.target:
        print(f"\n🕷️ Spidering {args.target}...")
        result = zap.spider_scan(args.target)
        if "success" in result:
            print(f"✅ Spider started! Scan ID: {result['scan_id']}")
        else:
            print(f"❌ Error: {result.get('error')}")
    
    elif args.active_scan and args.target:
        print(f"\n⚡ Active scan on {args.target}...")
        result = zap.active_scan(args.target)
        if "success" in result:
            print(f"✅ Active scan started! Scan ID: {result['scan_id']}")
        else:
            print(f"❌ Error: {result.get('error')}")
    
    elif args.alerts:
        alerts = zap.get_alerts(args.target, args.risk_level)
        print(f"\n🚨 Vulnerability Alerts: {len(alerts)}")
        for alert in alerts[:10]:
            print(f"\n   [{alert.get('risk')}] {alert.get('alert')}")
            print(f"   URL: {alert.get('url')}")
            print(f"   Description: {alert.get('description', 'N/A')[:100]}...")
    
    elif args.report:
        print(f"\n📄 Generating {args.report.upper()} report...")
        result = zap.generate_report(args.target, args.report, args.output)
        if "success" in result:
            print(f"✅ Report saved to {result['output']}")
        else:
            print(f"❌ Error: {result.get('error')}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
