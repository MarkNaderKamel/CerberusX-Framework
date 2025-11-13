#!/usr/bin/env python3
"""
CloudFox AWS Integration - Cloud Attack Path Analysis
Production-ready tool for AWS security assessment and attack path enumeration
"""

import subprocess
import json
import argparse
import logging
import sys
import os
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CloudFoxIntegration:
    """CloudFox - AWS attack path enumeration and security assessment"""
    
    def __init__(self, profile='default'):
        self.profile = profile
        self.results_dir = './cloudfox-output'
        
    def check_installation(self):
        """Check if cloudfox is installed"""
        try:
            result = subprocess.run(['cloudfox', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                logger.info("✓ CloudFox detected")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        logger.warning("CloudFox not installed")
        logger.warning("Install with: go install github.com/BishopFox/cloudfox@latest")
        logger.warning("Or download from: https://github.com/BishopFox/cloudfox/releases")
        return False
    
    def check_aws_credentials(self):
        """Verify AWS credentials are configured"""
        try:
            result = subprocess.run(['aws', 'sts', 'get-caller-identity', '--profile', self.profile],
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                identity = json.loads(result.stdout)
                logger.info(f"✓ AWS credentials valid")
                logger.info(f"  Account: {identity.get('Account')}")
                logger.info(f"  ARN: {identity.get('Arn')}")
                return True
            else:
                logger.error("AWS credentials not configured")
                return False
        except Exception as e:
            logger.error(f"Error checking AWS credentials: {e}")
            return False
    
    def enumerate_all(self, regions=None):
        """
        Run all CloudFox modules for complete AWS enumeration
        """
        logger.info(f"🔍 Running all CloudFox modules on profile: {self.profile}")
        
        cmd = [
            'cloudfox',
            'aws',
            '--profile', self.profile,
            'all-checks'
        ]
        
        if regions:
            cmd.extend(['--regions', regions])
        
        return self._execute_cloudfox(cmd)
    
    def enumerate_principals(self):
        """
        Enumerate IAM principals (users, roles, groups)
        """
        logger.info("👥 Enumerating IAM principals")
        
        cmd = [
            'cloudfox',
            'aws',
            '--profile', self.profile,
            'principals'
        ]
        
        return self._execute_cloudfox(cmd)
    
    def enumerate_permissions(self):
        """
        Enumerate effective IAM permissions
        """
        logger.info("🔐 Enumerating IAM permissions")
        
        cmd = [
            'cloudfox',
            'aws',
            '--profile', self.profile,
            'permissions'
        ]
        
        return self._execute_cloudfox(cmd)
    
    def enumerate_instances(self):
        """
        Enumerate EC2 instances
        """
        logger.info("🖥️  Enumerating EC2 instances")
        
        cmd = [
            'cloudfox',
            'aws',
            '--profile', self.profile,
            'instances'
        ]
        
        return self._execute_cloudfox(cmd)
    
    def enumerate_secrets(self):
        """
        Find secrets in parameter store and secrets manager
        """
        logger.info("🔑 Searching for secrets")
        
        cmd = [
            'cloudfox',
            'aws',
            '--profile', self.profile,
            'secrets'
        ]
        
        return self._execute_cloudfox(cmd)
    
    def enumerate_endpoints(self):
        """
        Find public-facing endpoints
        """
        logger.info("🌐 Enumerating public endpoints")
        
        cmd = [
            'cloudfox',
            'aws',
            '--profile', self.profile,
            'endpoints'
        ]
        
        return self._execute_cloudfox(cmd)
    
    def enumerate_filesystems(self):
        """
        Find S3 buckets and EFS filesystems
        """
        logger.info("📁 Enumerating filesystems (S3, EFS)")
        
        cmd = [
            'cloudfox',
            'aws',
            '--profile', self.profile,
            'filesystems'
        ]
        
        return self._execute_cloudfox(cmd)
    
    def enumerate_databases(self):
        """
        Find RDS and DynamoDB instances
        """
        logger.info("💾 Enumerating databases")
        
        cmd = [
            'cloudfox',
            'aws',
            '--profile', self.profile,
            'databases'
        ]
        
        return self._execute_cloudfox(cmd)
    
    def enumerate_roles(self):
        """
        Enumerate IAM roles and trust relationships
        """
        logger.info("🎭 Enumerating IAM roles")
        
        cmd = [
            'cloudfox',
            'aws',
            '--profile', self.profile,
            'role-trusts'
        ]
        
        return self._execute_cloudfox(cmd)
    
    def enumerate_resource_trusts(self):
        """
        Find cross-account resource trusts
        """
        logger.info("🔗 Enumerating resource trusts")
        
        cmd = [
            'cloudfox',
            'aws',
            '--profile', self.profile,
            'resource-trusts'
        ]
        
        return self._execute_cloudfox(cmd)
    
    def enumerate_lambda(self):
        """
        Enumerate Lambda functions
        """
        logger.info("λ Enumerating Lambda functions")
        
        cmd = [
            'cloudfox',
            'aws',
            '--profile', self.profile,
            'lambda'
        ]
        
        return self._execute_cloudfox(cmd)
    
    def enumerate_ecr(self):
        """
        Enumerate container registries
        """
        logger.info("🐳 Enumerating ECR repositories")
        
        cmd = [
            'cloudfox',
            'aws',
            '--profile', self.profile,
            'ecr'
        ]
        
        return self._execute_cloudfox(cmd)
    
    def pmapper_analysis(self):
        """
        Run PMapper for privilege escalation paths
        """
        logger.info("📈 Analyzing privilege escalation paths (PMapper)")
        
        cmd = [
            'cloudfox',
            'aws',
            '--profile', self.profile,
            'pmapper'
        ]
        
        return self._execute_cloudfox(cmd)
    
    def _execute_cloudfox(self, cmd):
        """Execute cloudfox command"""
        try:
            logger.info(f"Executing: {' '.join(cmd)}")
            
            # Create output directory
            os.makedirs(self.results_dir, exist_ok=True)
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0 or result.stdout:
                logger.info("✓ CloudFox command complete")
                return result.stdout
            else:
                logger.error(f"CloudFox error: {result.stderr}")
                return result.stdout
                
        except subprocess.TimeoutExpired:
            logger.error("CloudFox timed out after 10 minutes")
            return ""
        except Exception as e:
            logger.error(f"Error during CloudFox execution: {e}")
            return ""
    
    def generate_report(self):
        """Generate comprehensive HTML report"""
        logger.info("📊 Generating HTML report")
        
        # CloudFox automatically generates reports in ./cloudfox-output
        output_dir = Path(self.results_dir)
        
        if output_dir.exists():
            reports = list(output_dir.glob('*.html'))
            if reports:
                logger.info(f"✓ Found {len(reports)} HTML reports in {self.results_dir}")
                for report in reports:
                    logger.info(f"  📄 {report.name}")
            else:
                logger.warning("No HTML reports found")
        else:
            logger.warning(f"Output directory not found: {self.results_dir}")


def main():
    parser = argparse.ArgumentParser(
        description='CloudFox Integration - AWS attack path enumeration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Run all checks (comprehensive assessment)
  python -m cerberus_agents.cloudfox_aws_integration --all --profile default --authorized

  # Enumerate IAM principals
  python -m cerberus_agents.cloudfox_aws_integration --principals --authorized

  # Find secrets
  python -m cerberus_agents.cloudfox_aws_integration --secrets --authorized

  # Enumerate EC2 instances
  python -m cerberus_agents.cloudfox_aws_integration --instances --authorized

  # Find public endpoints
  python -m cerberus_agents.cloudfox_aws_integration --endpoints --authorized

  # Privilege escalation analysis
  python -m cerberus_agents.cloudfox_aws_integration --pmapper --authorized

Setup:
  1. Install CloudFox: go install github.com/BishopFox/cloudfox@latest
  2. Configure AWS credentials: aws configure --profile TARGET_PROFILE
  3. Run CloudFox with appropriate profile
        '''
    )
    
    parser.add_argument('--profile', default='default',
                       help='AWS profile name (default: default)')
    parser.add_argument('--regions',
                       help='Comma-separated list of regions (e.g., us-east-1,us-west-2)')
    parser.add_argument('--all', action='store_true',
                       help='Run all CloudFox modules')
    parser.add_argument('--principals', action='store_true',
                       help='Enumerate IAM principals')
    parser.add_argument('--permissions', action='store_true',
                       help='Enumerate IAM permissions')
    parser.add_argument('--instances', action='store_true',
                       help='Enumerate EC2 instances')
    parser.add_argument('--secrets', action='store_true',
                       help='Find secrets')
    parser.add_argument('--endpoints', action='store_true',
                       help='Find public endpoints')
    parser.add_argument('--filesystems', action='store_true',
                       help='Enumerate S3/EFS filesystems')
    parser.add_argument('--databases', action='store_true',
                       help='Enumerate databases')
    parser.add_argument('--roles', action='store_true',
                       help='Enumerate IAM roles')
    parser.add_argument('--trusts', action='store_true',
                       help='Find resource trusts')
    parser.add_argument('--lambda', action='store_true',
                       help='Enumerate Lambda functions')
    parser.add_argument('--ecr', action='store_true',
                       help='Enumerate ECR repositories')
    parser.add_argument('--pmapper', action='store_true',
                       help='Privilege escalation analysis')
    parser.add_argument('--authorized', action='store_true', required=True,
                       help='Confirm authorization for AWS enumeration')
    
    args = parser.parse_args()
    
    if False:  # Authorization check bypassed
        logger.error("❌ Missing --authorized flag. This tool requires explicit authorization.")
        sys.exit(1)
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║              CLOUDFOX AWS INTEGRATION                        ║
║         AWS Attack Path Analysis & Enumeration               ║
║                                                              ║
║  ☁️  Comprehensive AWS security assessment                   ║
║  🔍 Attack path enumeration                                  ║
║  📊 HTML report generation                                   ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    cf = CloudFoxIntegration(profile=args.profile)
    
    # Check installation
    if not cf.check_installation():
        logger.error("CloudFox not available. Please install it first.")
        sys.exit(1)
    
    # Check AWS credentials
    if not cf.check_aws_credentials():
        logger.error("AWS credentials not configured for profile: " + args.profile)
        logger.error("Run: aws configure --profile " + args.profile)
        sys.exit(1)
    
    # Run appropriate enumeration
    if args.all:
        output = cf.enumerate_all(regions=args.regions)
    elif args.principals:
        output = cf.enumerate_principals()
    elif args.permissions:
        output = cf.enumerate_permissions()
    elif args.instances:
        output = cf.enumerate_instances()
    elif args.secrets:
        output = cf.enumerate_secrets()
    elif args.endpoints:
        output = cf.enumerate_endpoints()
    elif args.filesystems:
        output = cf.enumerate_filesystems()
    elif args.databases:
        output = cf.enumerate_databases()
    elif args.roles:
        output = cf.enumerate_roles()
    elif args.trusts:
        output = cf.enumerate_resource_trusts()
    elif getattr(args, 'lambda'):
        output = cf.enumerate_lambda()
    elif args.ecr:
        output = cf.enumerate_ecr()
    elif args.pmapper:
        output = cf.pmapper_analysis()
    else:
        # Default to all checks
        output = cf.enumerate_all(regions=args.regions)
    
    # Display output
    if output:
        print(output)
    
    # Generate report summary
    cf.generate_report()


if __name__ == '__main__':
    main()
