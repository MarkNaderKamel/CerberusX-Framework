#!/usr/bin/env python3
"""
Prowler Cloud Security Compliance Scanner
CIS Benchmarks compliance for AWS, Azure, GCP
Production-ready cloud security posture assessment
"""

import subprocess
import json
import os
import logging
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ProwlerCloudCompliance:
    """Prowler CIS compliance scanner for multi-cloud environments"""
    
    def __init__(self):
        self.prowler_path = self._find_prowler()
    
    def _find_prowler(self) -> Optional[str]:
        """Locate Prowler installation"""
        if subprocess.run(["which", "prowler"], capture_output=True).returncode == 0:
            return "prowler"
        return None
    
    def check_installation(self) -> Dict[str, any]:
        """Check Prowler installation"""
        result = {
            "installed": False,
            "version": None,
            "install_commands": [
                "pip install prowler",
                "# Or via pipx:",
                "pipx install prowler"
            ]
        }
        
        if self.prowler_path:
            try:
                version_output = subprocess.check_output(
                    [self.prowler_path, "--version"],
                    stderr=subprocess.STDOUT,
                    timeout=5
                ).decode()
                result["installed"] = True
                result["version"] = version_output.strip()
            except Exception as e:
                logger.warning(f"Version check failed: {e}")
        
        return result
    
    def scan_aws(self, profile: str = None, region: str = None, 
                 services: List[str] = None, severity: str = "all",
                 output_formats: List[str] = None, output_dir: str = "./prowler_output") -> Dict[str, any]:
        """
        AWS security assessment
        
        Args:
            profile: AWS profile name
            region: AWS region (default: all regions)
            services: Services to scan (iam, s3, ec2, lambda, etc.)
            severity: critical, high, medium, low, informational, all
            output_formats: json, html, csv, json-asff, json-ocsf
        """
        if not self.prowler_path:
            return {"error": "Prowler not installed"}
        
        cmd = [self.prowler_path, "aws"]
        
        if profile:
            cmd.extend(["--profile", profile])
        if region:
            cmd.extend(["--region", region])
        if services:
            cmd.extend(["--services"] + services)
        if severity != "all":
            cmd.extend(["--severity", severity])
        
        output_formats = output_formats or ["json", "html"]
        cmd.extend(["--output-formats"] + output_formats)
        cmd.extend(["--output-directory", output_dir])
        
        try:
            logger.info(f"Running Prowler AWS scan: {' '.join(cmd)}")
            output = subprocess.check_output(
                cmd,
                stderr=subprocess.STDOUT,
                timeout=600
            ).decode()
            
            return {
                "success": True,
                "provider": "aws",
                "services": services or ["all"],
                "output_directory": output_dir,
                "output_formats": output_formats,
                "summary": output
            }
        except subprocess.TimeoutExpired:
            return {"error": "Scan timed out (>10 minutes)"}
        except Exception as e:
            return {"error": str(e)}
    
    def scan_azure(self, subscription_id: str = None, output_dir: str = "./prowler_output") -> Dict[str, any]:
        """Azure security assessment"""
        if not self.prowler_path:
            return {"error": "Prowler not installed"}
        
        cmd = [self.prowler_path, "azure"]
        if subscription_id:
            cmd.extend(["--subscription-id", subscription_id])
        cmd.extend(["--output-directory", output_dir])
        
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=600).decode()
            return {"success": True, "provider": "azure", "output": output_dir}
        except Exception as e:
            return {"error": str(e)}
    
    def scan_gcp(self, project_id: str = None, output_dir: str = "./prowler_output") -> Dict[str, any]:
        """GCP security assessment"""
        if not self.prowler_path:
            return {"error": "Prowler not installed"}
        
        cmd = [self.prowler_path, "gcp"]
        if project_id:
            cmd.extend(["--project-id", project_id])
        cmd.extend(["--output-directory", output_dir])
        
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=600).decode()
            return {"success": True, "provider": "gcp", "output": output_dir}
        except Exception as e:
            return {"error": str(e)}
    
    def quick_aws_scan(self, critical_only: bool = True) -> Dict[str, any]:
        """Quick AWS scan for critical issues only"""
        services = ["iam", "s3", "ec2", "lambda", "rds"]
        severity = "critical" if critical_only else "all"
        return self.scan_aws(services=services, severity=severity)
    
    def compliance_scan(self, framework: str = "cis", provider: str = "aws") -> Dict[str, any]:
        """
        Run compliance framework scan
        
        Args:
            framework: cis, pci-dss, hipaa, iso27001, gdpr, soc2
            provider: aws, azure, gcp
        """
        if not self.prowler_path:
            return {"error": "Prowler not installed"}
        
        cmd = [self.prowler_path, provider, "--compliance", framework]
        
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=600).decode()
            return {"success": True, "framework": framework, "provider": provider}
        except Exception as e:
            return {"error": str(e)}
    
    def get_info(self) -> Dict[str, any]:
        """Get Prowler information"""
        return {
            "name": "Prowler Cloud Security Scanner",
            "description": "CIS Benchmarks compliance for AWS, Azure, GCP",
            "features": [
                "CIS Benchmarks compliance scanning",
                "AWS, Azure, GCP support",
                "PCI-DSS, HIPAA, GDPR, ISO 27001, SOC 2 frameworks",
                "JSON, HTML, CSV output formats",
                "Integration with Security Hub, S3",
                "400+ security checks",
                "Role-based authentication",
                "Multi-account scanning"
            ],
            "supported_clouds": ["AWS", "Azure", "GCP", "Kubernetes"],
            "compliance_frameworks": [
                "CIS Benchmarks",
                "PCI-DSS",
                "HIPAA",
                "ISO 27001",
                "GDPR",
                "SOC 2",
                "ENS (Spain)",
                "NIST 800-53"
            ],
            "aws_services": [
                "IAM", "S3", "EC2", "Lambda", "RDS", "CloudTrail",
                "VPC", "KMS", "ELB", "CloudFront", "Route53", "SQS"
            ],
            "output_formats": ["json", "html", "csv", "json-asff", "json-ocsf"],
            "github": "https://github.com/prowler-cloud/prowler"
        }


def main():
    """CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Prowler Cloud Compliance Scanner")
    parser.add_argument("--check", action="store_true", help="Check installation")
    parser.add_argument("--info", action="store_true", help="Show scanner info")
    parser.add_argument("--provider", choices=["aws", "azure", "gcp"], help="Cloud provider")
    parser.add_argument("--profile", help="AWS profile name")
    parser.add_argument("--region", help="AWS region")
    parser.add_argument("--services", nargs="+", help="Services to scan")
    parser.add_argument("--severity", default="all", 
                       choices=["critical", "high", "medium", "low", "informational", "all"])
    parser.add_argument("--quick", action="store_true", help="Quick critical issues scan (AWS)")
    parser.add_argument("--compliance", help="Compliance framework (cis, pci-dss, hipaa, etc.)")
    parser.add_argument("--output-dir", default="./prowler_output", help="Output directory")
    parser.add_argument('--authorized', action='store_true',
                       help='Confirm you have authorization to perform this action')
    args = parser.parse_args()
    
    prowler = ProwlerCloudCompliance()
    
    if args.check:
        status = prowler.check_installation()
        print("\n═══ Prowler Installation Status ═══")
        print(f"Installed: {status['installed']}")
        if status['installed']:
            print(f"Version: {status['version']}")
        else:
            print(f"\n📥 Installation Commands:")
            for cmd in status['install_commands']:
                print(f"   {cmd}")
    
    elif args.info:
        info = prowler.get_info()
        print("\n═══ Prowler Cloud Security Scanner ═══")
        print(f"Name: {info['name']}")
        print(f"Description: {info['description']}")
        print(f"\n🎯 Features:")
        for feature in info['features']:
            print(f"   • {feature}")
        print(f"\n☁️ Supported Clouds: {', '.join(info['supported_clouds'])}")
        print(f"\n📋 Compliance Frameworks:")
        for framework in info['compliance_frameworks']:
            print(f"   • {framework}")
        print(f"\n🔗 GitHub: {info['github']}")
    
    elif args.quick:
        print("\n🚀 Running quick AWS critical issues scan...")
        result = prowler.quick_aws_scan()
        if "success" in result:
            print(f"✅ Scan complete! Results: {result['output_directory']}")
        else:
            print(f"❌ Error: {result.get('error')}")
    
    elif args.compliance and args.provider:
        print(f"\n📋 Running {args.compliance.upper()} compliance scan on {args.provider.upper()}...")
        result = prowler.compliance_scan(args.compliance, args.provider)
        if "success" in result:
            print("✅ Compliance scan complete!")
        else:
            print(f"❌ Error: {result.get('error')}")
    
    elif args.provider == "aws":
        print("\n🔍 Running AWS security assessment...")
        result = prowler.scan_aws(
            profile=args.profile,
            region=args.region,
            services=args.services,
            severity=args.severity,
            output_dir=args.output_dir
        )
        if "success" in result:
            print(f"✅ Scan complete! Results: {result['output_directory']}")
        else:
            print(f"❌ Error: {result.get('error')}")
    
    elif args.provider == "azure":
        print("\n🔍 Running Azure security assessment...")
        result = prowler.scan_azure(output_dir=args.output_dir)
        if "success" in result:
            print("✅ Scan complete!")
        else:
            print(f"❌ Error: {result.get('error')}")
    
    elif args.provider == "gcp":
        print("\n🔍 Running GCP security assessment...")
        result = prowler.scan_gcp(output_dir=args.output_dir)
        if "success" in result:
            print("✅ Scan complete!")
        else:
            print(f"❌ Error: {result.get('error')}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
