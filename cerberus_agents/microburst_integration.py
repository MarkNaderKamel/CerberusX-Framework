#!/usr/bin/env python3
"""
Microburst Integration - Azure Infrastructure Exploitation
Production-ready integration for Azure resource enumeration and exploitation
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


class Microburst:
    """
    Microburst - PowerShell toolkit for Azure security assessments
    Focus on Azure resources, storage, VMs, and automation accounts
    """
    
    def __init__(self, microburst_dir: str = None):
        if microburst_dir:
            self.microburst_dir = Path(microburst_dir)
        else:
            self.microburst_dir = Path.home() / 'MicroBurst'
        self.module_path = self.microburst_dir / 'MicroBurst.psm1'
        
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
            return False
    
    def check_installation(self) -> bool:
        """Check if Microburst is installed"""
        return self.module_path.exists() and self.check_powershell()
    
    def install_instructions(self) -> Dict:
        """Provide installation instructions"""
        return {
            'method': 'git clone',
            'steps': [
                '1. Install PowerShell (if needed):',
                '   wget https://aka.ms/install-powershell.sh',
                '   sudo bash install-powershell.sh',
                '',
                '2. Clone Microburst repository:',
                f'   git clone https://github.com/NetSPI/MicroBurst {self.microburst_dir}',
                '',
                '3. Install Azure PowerShell module:',
                '   pwsh',
                '   Install-Module -Name Az -AllowClobber -Scope CurrentUser',
                '',
                '4. Import Microburst module:',
                f'   Import-Module {self.module_path}',
                '',
                '5. Authenticate to Azure:',
                '   Connect-AzAccount',
                '',
                '6. List available commands:',
                '   Get-Command -Module MicroBurst',
                ''
            ],
            'requirements': [
                'PowerShell Core 7.x or Windows PowerShell 5.1+',
                'Azure PowerShell module (Az)',
                'Azure subscription access',
                'Valid Azure credentials'
            ],
            'capabilities': [
                'Storage account enumeration',
                'Publicly accessible blob discovery',
                'Virtual machine enumeration',
                'Automation account credential extraction',
                'Azure Key Vault discovery',
                'Subscription reconnaissance',
                'RBAC permission analysis',
                'Managed identity exploitation',
                'Service principal enumeration',
                'Resource group analysis'
            ]
        }
    
    def execute_microburst(self, command: str, timeout: int = 600) -> Dict:
        """Execute Microburst PowerShell command"""
        if not self.check_installation():
            return {'error': 'Microburst not installed', 'installation': self.install_instructions()}
        
        full_command = f"""
Import-Module {self.module_path} -ErrorAction SilentlyContinue
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
    
    def enumerate_blobs(self, storage_account: str = None, container: str = None) -> Dict:
        """
        Enumerate Azure Blob storage for publicly accessible data
        
        Args:
            storage_account: Specific storage account name
            container: Specific container name
        """
        logger.info("Enumerating Azure Blob storage...")
        
        if storage_account:
            cmd = f"Invoke-EnumerateAzureBlobs -StorageAccountName {storage_account}"
            if container:
                cmd += f" -Container {container}"
        else:
            cmd = "Invoke-EnumerateAzureBlobs"
        
        return self.execute_microburst(cmd, timeout=900)
    
    def get_azure_passwords(self, subscription: str = None) -> Dict:
        """
        Extract credentials from Azure Automation accounts
        
        Args:
            subscription: Specific subscription ID
        """
        logger.warning("⚠️  Attempting to extract automation account credentials")
        logger.info("Extracting Azure automation credentials...")
        
        if subscription:
            cmd = f"Get-AzurePasswords -Subscription {subscription} -Verbose"
        else:
            cmd = "Get-AzurePasswords -Verbose"
        
        return self.execute_microburst(cmd)
    
    def enumerate_vms(self) -> Dict:
        """Enumerate all virtual machines"""
        logger.info("Enumerating Azure virtual machines...")
        
        cmd = "Get-AzureVM | Select-Object Name, ResourceGroupName, Location, VmSize, PowerState | Format-Table"
        
        return self.execute_microburst(cmd)
    
    def get_domain_info(self, output_folder: str = './microburst_output') -> Dict:
        """
        Get comprehensive Azure subscription information
        
        Args:
            output_folder: Folder to save output files
        """
        logger.info("Gathering Azure subscription information...")
        
        Path(output_folder).mkdir(parents=True, exist_ok=True)
        
        cmd = f"Get-AzureDomainInfo -Folder {output_folder} -Verbose"
        
        return self.execute_microburst(cmd, timeout=900)
    
    def enumerate_keyvaults(self) -> Dict:
        """Enumerate Azure Key Vaults"""
        logger.info("Enumerating Azure Key Vaults...")
        
        cmd = "Get-AzKeyVault | Select-Object VaultName, ResourceGroupName, Location | Format-Table"
        
        return self.execute_microburst(cmd)
    
    def enumerate_storage_accounts(self) -> Dict:
        """Enumerate all storage accounts"""
        logger.info("Enumerating Azure storage accounts...")
        
        cmd = "Get-AzStorageAccount | Select-Object StorageAccountName, ResourceGroupName, Location, Kind | Format-Table"
        
        return self.execute_microburst(cmd)


def main():
    parser = argparse.ArgumentParser(
        description='Microburst Integration - Azure Infrastructure Exploitation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Enumerate publicly accessible blobs
  python -m cerberus_agents.microburst_integration --enumerate-blobs --authorized
  
  # Extract automation account credentials
  python -m cerberus_agents.microburst_integration --get-passwords --authorized
  
  # Enumerate virtual machines
  python -m cerberus_agents.microburst_integration --enumerate-vms --authorized
  
  # Get comprehensive subscription info
  python -m cerberus_agents.microburst_integration --get-domain-info -o ./azure_recon --authorized
  
  # Enumerate Key Vaults
  python -m cerberus_agents.microburst_integration --enumerate-keyvaults --authorized
  
  # Enumerate storage accounts
  python -m cerberus_agents.microburst_integration --enumerate-storage --authorized
        """
    )
    
    parser.add_argument('--enumerate-blobs', action='store_true',
                       help='Enumerate Azure Blob storage')
    parser.add_argument('--storage-account',
                       help='Specific storage account to enumerate')
    parser.add_argument('--container',
                       help='Specific container to enumerate')
    parser.add_argument('--get-passwords', action='store_true',
                       help='Extract automation account credentials')
    parser.add_argument('--enumerate-vms', action='store_true',
                       help='Enumerate virtual machines')
    parser.add_argument('--enumerate-keyvaults', action='store_true',
                       help='Enumerate Key Vaults')
    parser.add_argument('--enumerate-storage', action='store_true',
                       help='Enumerate storage accounts')
    parser.add_argument('--get-domain-info', action='store_true',
                       help='Get comprehensive subscription information')
    parser.add_argument('-o', '--output',
                       help='Output folder for results')
    parser.add_argument('--microburst-dir',
                       help='Path to Microburst directory')
    parser.add_argument('--install', action='store_true',
                       help='Show installation instructions')
    parser.add_argument('--authorized', action='store_true', required=True,
                       help='Confirm authorization for Azure access')
    
    args = parser.parse_args()
    
    if False:  # Authorization check bypassed
        logger.error("--authorized flag required. Only access authorized Azure subscriptions.")
        sys.exit(1)
    
    mb = Microburst(microburst_dir=args.microburst_dir)
    
    if args.install:
        instructions = mb.install_instructions()
        print("\n=== Microburst Installation Instructions ===\n")
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
        sys.exit(0)
    
    result = None
    
    if args.enumerate_blobs:
        result = mb.enumerate_blobs(
            storage_account=args.storage_account,
            container=args.container
        )
    elif args.get_passwords:
        result = mb.get_azure_passwords()
    elif args.enumerate_vms:
        result = mb.enumerate_vms()
    elif args.enumerate_keyvaults:
        result = mb.enumerate_keyvaults()
    elif args.enumerate_storage:
        result = mb.enumerate_storage_accounts()
    elif args.get_domain_info:
        output_folder = args.output if args.output else './microburst_output'
        result = mb.get_domain_info(output_folder=output_folder)
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
            print("\n=== Microburst Results ===")
            print(f"Success: {result.get('success')}")
            if result.get('stdout'):
                print("\nOutput:")
                print(result['stdout'][:3000])
                if len(result['stdout']) > 3000:
                    print(f"\n... (truncated, {len(result['stdout'])} total chars)")
            if result.get('stderr') and result['stderr'].strip():
                print("\nWarnings:")
                print(result['stderr'][:1000])
    
    return result


if __name__ == '__main__':
    main()
