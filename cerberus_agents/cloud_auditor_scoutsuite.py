#!/usr/bin/env python3
"""
Cloud Security Auditor - Scout Suite Integration
Multi-cloud security auditing for AWS, Azure, GCP, Alibaba Cloud, Oracle Cloud
Production-ready cloud security posture assessment
"""

import subprocess
import json
import logging
import argparse
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CloudAuditor:
    """
    Production cloud security auditor using Scout Suite
    Supports AWS, Azure, GCP, Alibaba Cloud, Oracle Cloud
    """
    
    SUPPORTED_PROVIDERS = ['aws', 'azure', 'gcp', 'aliyun', 'oci']
    
    def __init__(self, output_dir: str = './scout_reports'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
    def check_installation(self) -> bool:
        """Check if Scout Suite is installed"""
        try:
            result = subprocess.run(['scout', '--help'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                logger.info("Scout Suite is installed")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        logger.error("Scout Suite not installed. Install with: pip install scoutsuite")
        return False
    
    def audit_aws(self, profile: Optional[str] = None, 
                 regions: Optional[List[str]] = None,
                 services: Optional[List[str]] = None) -> Dict:
        """
        Audit AWS environment
        
        Args:
            profile: AWS profile name (uses default if None)
            regions: List of regions to scan (all if None)
            services: Specific services to audit
        """
        if not self.check_installation():
            return {"error": "Scout Suite not installed"}
        
        cmd = [
            'scout', 'aws',
            '--report-dir', self.output_dir,
            '--no-browser'
        ]
        
        if profile:
            cmd.extend(['--profile', profile])
        
        if regions:
            cmd.extend(['--regions', ','.join(regions)])
        
        if services:
            cmd.extend(['--services', ','.join(services)])
        
        logger.info(f"Starting AWS security audit...")
        logger.info(f"Command: {' '.join(cmd)}")
        
        return self._run_scan('aws', cmd)
    
    def audit_azure(self, tenant_id: Optional[str] = None,
                   subscription_ids: Optional[List[str]] = None) -> Dict:
        """
        Audit Azure environment
        
        Requires Azure CLI authentication: az login
        """
        if not self.check_installation():
            return {"error": "Scout Suite not installed"}
        
        cmd = [
            'scout', 'azure',
            '--report-dir', self.output_dir,
            '--no-browser'
        ]
        
        if tenant_id:
            cmd.extend(['--tenant-id', tenant_id])
        
        if subscription_ids:
            cmd.extend(['--subscription-ids', ','.join(subscription_ids)])
        
        logger.info("Starting Azure security audit...")
        logger.info(f"Command: {' '.join(cmd)}")
        
        return self._run_scan('azure', cmd)
    
    def audit_gcp(self, project_id: str, 
                 service_account: Optional[str] = None) -> Dict:
        """
        Audit GCP environment
        
        Args:
            project_id: GCP project ID
            service_account: Path to service account JSON key
        """
        if not self.check_installation():
            return {"error": "Scout Suite not installed"}
        
        cmd = [
            'scout', 'gcp',
            '--project-id', project_id,
            '--report-dir', self.output_dir,
            '--no-browser'
        ]
        
        if service_account:
            cmd.extend(['--service-account', service_account])
        
        logger.info(f"Starting GCP security audit for project {project_id}...")
        logger.info(f"Command: {' '.join(cmd)}")
        
        return self._run_scan('gcp', cmd)
    
    def _run_scan(self, provider: str, cmd: List[str]) -> Dict:
        """Execute Scout Suite scan"""
        start_time = datetime.now()
        
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE, text=True)
            
            stdout, stderr = process.communicate(timeout=3600)
            
            if process.returncode == 0:
                logger.info(f"{provider.upper()} audit completed successfully")
                
                # Parse results
                results = self._parse_results(provider)
                
                duration = (datetime.now() - start_time).total_seconds()
                
                return {
                    "provider": provider,
                    "status": "success",
                    "duration_seconds": duration,
                    "report_location": self.output_dir,
                    "findings": results
                }
            else:
                logger.error(f"Scan failed: {stderr}")
                return {
                    "provider": provider,
                    "status": "failed",
                    "error": stderr
                }
                
        except subprocess.TimeoutExpired:
            logger.error("Scan timeout (1 hour)")
            return {"error": "Scan timeout"}
        except Exception as e:
            logger.error(f"Scan error: {e}")
            return {"error": str(e)}
    
    def _parse_results(self, provider: str) -> Dict:
        """Parse Scout Suite JSON results"""
        results_file = Path(self.output_dir) / f'scoutsuite-results/scoutsuite_results_{provider}.js'
        
        if not results_file.exists():
            # Try alternative location
            results_file = Path(self.output_dir) / f'scoutsuite_results_{provider}.js'
        
        if not results_file.exists():
            logger.warning(f"Results file not found: {results_file}")
            return {}
        
        try:
            with open(results_file, 'r') as f:
                content = f.read()
                # Scout Suite wraps JSON in JavaScript
                json_str = content.split('=', 1)[1].strip().rstrip(';')
                data = json.loads(json_str)
                
                return {
                    "total_rules": len(data.get('ruleset', {}).get('rules', [])),
                    "services_audited": list(data.get('services', {}).keys()),
                    "summary": self._summarize_findings(data)
                }
        except Exception as e:
            logger.error(f"Error parsing results: {e}")
            return {}
    
    def _summarize_findings(self, data: Dict) -> Dict:
        """Summarize findings by severity"""
        summary = {
            "danger": 0,
            "warning": 0,
            "info": 0
        }
        
        for service_name, service_data in data.get('services', {}).items():
            findings = service_data.get('findings', {})
            for finding_name, finding_data in findings.items():
                level = finding_data.get('level', 'info')
                if level in summary:
                    summary[level] += len(finding_data.get('items', []))
        
        return summary
    
    def generate_compliance_report(self, provider: str, 
                                  framework: str = 'CIS') -> str:
        """
        Generate compliance report (CIS, PCI-DSS, HIPAA, etc.)
        
        Note: Scout Suite includes compliance mapping in reports
        """
        report = f"""
        {'='*80}
        CLOUD SECURITY COMPLIANCE REPORT
        {'='*80}
        
        Provider: {provider.upper()}
        Framework: {framework}
        Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        Report Location: {self.output_dir}
        
        Open the HTML report for detailed compliance mapping:
        file://{os.path.abspath(self.output_dir)}/report.html
        
        Scout Suite automatically maps findings to:
        - CIS Benchmarks
        - PCI-DSS
        - HIPAA
        - GDPR
        - And more...
        
        {'='*80}
        """
        
        return report


class AWSSecurityChecker:
    """
    Additional AWS-specific security checks using boto3
    Complements Scout Suite with real-time checks
    """
    
    def __init__(self):
        try:
            import boto3
            self.boto3 = boto3
            self.session = boto3.Session()
        except ImportError:
            logger.error("boto3 not installed. Install with: pip install boto3")
            self.boto3 = None
    
    def check_public_s3_buckets(self) -> List[Dict]:
        """Find publicly accessible S3 buckets"""
        if not self.boto3:
            return []
        
        s3 = self.session.client('s3')
        public_buckets = []
        
        try:
            buckets = s3.list_buckets()['Buckets']
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                try:
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl['Grants']:
                        grantee = grant.get('Grantee', {})
                        if grantee.get('Type') == 'Group' and 'AllUsers' in grantee.get('URI', ''):
                            public_buckets.append({
                                'bucket': bucket_name,
                                'permission': grant['Permission'],
                                'risk': 'HIGH'
                            })
                            logger.warning(f"Public bucket found: {bucket_name}")
                except Exception as e:
                    logger.debug(f"Error checking bucket {bucket_name}: {e}")
            
            return public_buckets
            
        except Exception as e:
            logger.error(f"Error listing S3 buckets: {e}")
            return []
    
    def check_security_groups(self, regions: Optional[List[str]] = None) -> List[Dict]:
        """Find overly permissive security groups"""
        if not self.boto3:
            return []
        
        if not regions:
            ec2 = self.session.client('ec2')
            regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
        
        risky_rules = []
        
        for region in regions:
            try:
                ec2 = self.session.client('ec2', region_name=region)
                sgs = ec2.describe_security_groups()['SecurityGroups']
                
                for sg in sgs:
                    for rule in sg.get('IpPermissions', []):
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                risky_rules.append({
                                    'region': region,
                                    'group_id': sg['GroupId'],
                                    'group_name': sg['GroupName'],
                                    'protocol': rule.get('IpProtocol', 'all'),
                                    'port': rule.get('FromPort', 'all'),
                                    'risk': 'HIGH'
                                })
                                logger.warning(f"Open security group: {sg['GroupId']} in {region}")
            
            except Exception as e:
                logger.debug(f"Error checking region {region}: {e}")
        
        return risky_rules
    
    def check_iam_users_without_mfa(self) -> List[str]:
        """Find IAM users without MFA enabled"""
        if not self.boto3:
            return []
        
        iam = self.session.client('iam')
        users_without_mfa = []
        
        try:
            users = iam.list_users()['Users']
            
            for user in users:
                username = user['UserName']
                mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
                
                if not mfa_devices:
                    users_without_mfa.append(username)
                    logger.warning(f"User without MFA: {username}")
            
            return users_without_mfa
            
        except Exception as e:
            logger.error(f"Error checking IAM users: {e}")
            return []


def main():
    parser = argparse.ArgumentParser(description="Multi-Cloud Security Auditor")
    parser.add_argument('--provider', required=True, 
                       choices=CloudAuditor.SUPPORTED_PROVIDERS,
                       help='Cloud provider to audit')
    parser.add_argument('--output-dir', default='./scout_reports',
                       help='Output directory for reports')
    
    # AWS options
    parser.add_argument('--aws-profile', help='AWS profile name')
    parser.add_argument('--aws-regions', nargs='+', help='AWS regions to scan')
    parser.add_argument('--aws-services', nargs='+', help='AWS services to audit')
    parser.add_argument('--check-s3', action='store_true', help='Check public S3 buckets')
    parser.add_argument('--check-sg', action='store_true', help='Check security groups')
    parser.add_argument('--check-iam', action='store_true', help='Check IAM users')
    
    # Azure options
    parser.add_argument('--azure-tenant', help='Azure tenant ID')
    parser.add_argument('--azure-subscriptions', nargs='+', help='Azure subscription IDs')
    
    # GCP options
    parser.add_argument('--gcp-project', help='GCP project ID')
    parser.add_argument('--gcp-service-account', help='GCP service account JSON')
    
        parser.add_argument('--authorized', action='store_true',
                       help='Confirm you have authorization to perform this action')
    args = parser.parse_args()
    
    auditor = CloudAuditor(output_dir=args.output_dir)
    
    if args.provider == 'aws':
        if args.check_s3 or args.check_sg or args.check_iam:
            # Run real-time AWS checks
            checker = AWSSecurityChecker()
            
            if args.check_s3:
                print("\n[+] Checking for public S3 buckets...")
                public_buckets = checker.check_public_s3_buckets()
                print(f"Found {len(public_buckets)} public buckets")
                for bucket in public_buckets:
                    print(f"  - {bucket['bucket']} ({bucket['permission']})")
            
            if args.check_sg:
                print("\n[+] Checking security groups...")
                risky_sgs = checker.check_security_groups(args.aws_regions)
                print(f"Found {len(risky_sgs)} risky security group rules")
                for sg in risky_sgs[:10]:  # Show first 10
                    print(f"  - {sg['group_id']} ({sg['region']}) - Port {sg['port']} open to 0.0.0.0/0")
            
            if args.check_iam:
                print("\n[+] Checking IAM users...")
                users_no_mfa = checker.check_iam_users_without_mfa()
                print(f"Found {len(users_no_mfa)} users without MFA")
                for user in users_no_mfa:
                    print(f"  - {user}")
        else:
            # Run full Scout Suite audit
            results = auditor.audit_aws(profile=args.aws_profile,
                                       regions=args.aws_regions,
                                       services=args.aws_services)
            print(json.dumps(results, indent=2))
            
    elif args.provider == 'azure':
        results = auditor.audit_azure(tenant_id=args.azure_tenant,
                                     subscription_ids=args.azure_subscriptions)
        print(json.dumps(results, indent=2))
        
    elif args.provider == 'gcp':
        if not args.gcp_project:
            print("Error: --gcp-project required for GCP audits")
            return
        
        results = auditor.audit_gcp(project_id=args.gcp_project,
                                   service_account=args.gcp_service_account)
        print(json.dumps(results, indent=2))
    
    print(f"\n[+] Full HTML report available at: {args.output_dir}/report.html")
    print("[+] Installation instructions:")
    print("    pip install scoutsuite boto3")
    print("    AWS: Configure credentials with 'aws configure'")
    print("    Azure: Login with 'az login'")
    print("    GCP: Set up service account JSON")


if __name__ == "__main__":
    main()
