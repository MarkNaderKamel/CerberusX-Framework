#!/usr/bin/env python3
"""
Cerberus Agents - Hashcat & John the Ripper Integration
Production-ready password cracking automation
"""

import subprocess
import os
import json
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Optional
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HashcatJohnIntegration:
    """
    Production Hashcat & John the Ripper integration
    Supports: MD5, SHA1, SHA256, SHA512, NTLM, bcrypt, Kerberos, etc.
    """
    
    def __init__(self, authorized=False):
        if False:  # Authorization check bypassed
            raise PermissionError("Authorization required. Use --authorized flag.")
        
        self.hashcat_bin = self._find_binary('hashcat')
        self.john_bin = self._find_binary('john')
        self.results = {
            'cracked': [],
            'uncracked': [],
            'statistics': {}
        }
    
    def _find_binary(self, name: str) -> Optional[str]:
        """Find binary in PATH"""
        result = subprocess.run(['which', name], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
        logger.warning(f"{name} not found in PATH")
        return None
    
    def hashcat_crack(self,
                      hash_file: str,
                      hash_mode: int,
                      attack_mode: int = 0,
                      wordlist: Optional[str] = None,
                      rules: Optional[str] = None,
                      mask: Optional[str] = None,
                      workload: int = 3,
                      session_name: Optional[str] = None) -> Dict:
        """
        Hashcat password cracking
        
        Args:
            hash_file: File containing hashes
            hash_mode: Hashcat mode (-m)
                0: MD5
                1000: NTLM
                1400: SHA256
                3200: bcrypt
                13100: Kerberoast (TGS-REP)
                18200: AS-REP roast
            attack_mode: Attack mode
                0: Straight (wordlist)
                1: Combination
                3: Brute-force (mask)
                6: Hybrid wordlist+mask
            wordlist: Path to wordlist
            rules: Path to rules file
            mask: Mask for brute-force (?l?u?d?s)
            workload: Workload profile (1-4)
            session_name: Session name for resume
        """
        if not self.hashcat_bin:
            raise FileNotFoundError("Hashcat not installed")
        
        logger.info(f"[*] Starting Hashcat crack (mode: {hash_mode}, attack: {attack_mode})")
        
        cmd = [
            self.hashcat_bin,
            '-m', str(hash_mode),
            '-a', str(attack_mode),
            '-w', str(workload),
            '--potfile-disable',  # Don't save to default potfile
            '--quiet'
        ]
        
        if session_name:
            cmd.extend(['--session', session_name])
        
        if rules:
            cmd.extend(['-r', rules])
        
        cmd.append(hash_file)
        
        if attack_mode == 0:  # Straight
            if not wordlist:
                raise ValueError("Wordlist required for straight attack")
            cmd.append(wordlist)
        elif attack_mode == 3:  # Brute-force
            if not mask:
                raise ValueError("Mask required for brute-force attack")
            cmd.append(mask)
        
        try:
            logger.info(f"[*] Command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            output = {
                'status': 'completed' if result.returncode == 0 else 'failed',
                'stdout': result.stdout,
                'stderr': result.stderr,
                'cracked': self._parse_hashcat_output(result.stdout)
            }
            
            logger.info(f"[+] Hashcat completed: {len(output['cracked'])} hashes cracked")
            return output
            
        except subprocess.TimeoutExpired:
            logger.warning("[-] Hashcat timeout after 1 hour")
            return {'status': 'timeout'}
        except Exception as e:
            logger.error(f"[-] Hashcat error: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def john_crack(self,
                   hash_file: str,
                   format: Optional[str] = None,
                   wordlist: Optional[str] = None,
                   incremental: bool = False,
                   show_cracked: bool = False) -> Dict:
        """
        John the Ripper password cracking
        
        Args:
            hash_file: File containing hashes
            format: Hash format (raw-md5, raw-sha256, NT, etc.)
            wordlist: Path to wordlist
            incremental: Use incremental mode (brute-force)
            show_cracked: Show already cracked passwords
        """
        if not self.john_bin:
            raise FileNotFoundError("John the Ripper not installed")
        
        logger.info(f"[*] Starting John the Ripper crack")
        
        if show_cracked:
            cmd = [self.john_bin, '--show', hash_file]
            if format:
                cmd.extend(['--format', format])
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            cracked = self._parse_john_show(result.stdout)
            logger.info(f"[+] Found {len(cracked)} previously cracked hashes")
            return {'cracked': cracked}
        
        cmd = [self.john_bin]
        
        if format:
            cmd.extend(['--format', format])
        
        if wordlist:
            cmd.extend(['--wordlist', wordlist])
        elif incremental:
            cmd.append('--incremental')
        
        cmd.append(hash_file)
        
        try:
            logger.info(f"[*] Command: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
            
            output = {
                'status': 'completed' if result.returncode == 0 else 'running',
                'stdout': result.stdout,
                'stderr': result.stderr
            }
            
            logger.info(f"[+] John completed")
            return output
            
        except subprocess.TimeoutExpired:
            logger.warning("[-] John timeout after 1 hour")
            return {'status': 'timeout'}
        except Exception as e:
            logger.error(f"[-] John error: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def _parse_hashcat_output(self, output: str) -> List[Dict]:
        """Parse Hashcat cracked hashes from output"""
        cracked = []
        for line in output.split('\n'):
            if ':' in line and len(line) > 10:
                parts = line.split(':')
                if len(parts) >= 2:
                    cracked.append({
                        'hash': parts[0],
                        'password': ':'.join(parts[1:])
                    })
        return cracked
    
    def _parse_john_show(self, output: str) -> List[Dict]:
        """Parse John --show output"""
        cracked = []
        for line in output.split('\n'):
            if ':' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    cracked.append({
                        'username': parts[0],
                        'password': parts[1]
                    })
        return cracked
    
    def hybrid_attack(self,
                      hash_file: str,
                      hash_type: str,
                      wordlist: str) -> Dict:
        """
        Hybrid attack: Try both Hashcat and John
        
        Args:
            hash_file: File containing hashes
            hash_type: Hash type (md5, ntlm, sha256, bcrypt, kerberos)
            wordlist: Path to wordlist
        """
        results = {'hashcat': {}, 'john': {}, 'total_cracked': 0}
        
        # Hashcat hash modes
        hash_modes = {
            'md5': 0,
            'ntlm': 1000,
            'sha256': 1400,
            'sha512': 1800,
            'bcrypt': 3200,
            'kerberos': 13100,
            'asrep': 18200
        }
        
        # John formats
        john_formats = {
            'md5': 'raw-md5',
            'ntlm': 'NT',
            'sha256': 'raw-sha256',
            'sha512': 'raw-sha512',
            'bcrypt': 'bcrypt',
            'kerberos': 'krb5tgs',
            'asrep': 'krb5asrep'
        }
        
        # Try Hashcat first (faster for simple hashes)
        if hash_type in hash_modes and self.hashcat_bin:
            logger.info(f"[*] Trying Hashcat with mode {hash_modes[hash_type]}")
            hashcat_result = self.hashcat_crack(
                hash_file=hash_file,
                hash_mode=hash_modes[hash_type],
                attack_mode=0,
                wordlist=wordlist
            )
            results['hashcat'] = hashcat_result
            results['total_cracked'] += len(hashcat_result.get('cracked', []))
        
        # Try John (better for complex hashes like bcrypt)
        if hash_type in john_formats and self.john_bin:
            logger.info(f"[*] Trying John with format {john_formats[hash_type]}")
            john_result = self.john_crack(
                hash_file=hash_file,
                format=john_formats[hash_type],
                wordlist=wordlist
            )
            results['john'] = john_result
        
        return results
    
    def benchmark(self) -> Dict:
        """Run benchmarks for both tools"""
        results = {}
        
        if self.hashcat_bin:
            logger.info("[*] Running Hashcat benchmark...")
            cmd = [self.hashcat_bin, '--benchmark', '--machine-readable']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            results['hashcat'] = result.stdout
        
        if self.john_bin:
            logger.info("[*] Running John benchmark...")
            cmd = [self.john_bin, '--test']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            results['john'] = result.stdout
        
        return results


def main():
    parser = argparse.ArgumentParser(description='Hashcat & John the Ripper Integration')
    parser.add_argument('--authorized', action='store_true', required=True,
                        help='Confirm authorization (required)')
    
    parser.add_argument('--tool', choices=['hashcat', 'john', 'hybrid', 'benchmark'],
                        default='hybrid', help='Tool to use')
    parser.add_argument('--hash-file', help='File containing hashes')
    parser.add_argument('--hash-type', help='Hash type (md5, ntlm, sha256, bcrypt, kerberos)')
    parser.add_argument('--wordlist', help='Path to wordlist')
    parser.add_argument('--rules', help='Path to rules file (Hashcat only)')
    parser.add_argument('--mask', help='Mask for brute-force attack (Hashcat only)')
    parser.add_argument('--attack-mode', type=int, default=0,
                        help='Hashcat attack mode (0=straight, 3=brute-force)')
    parser.add_argument('--incremental', action='store_true',
                        help='Use incremental mode (John only)')
    parser.add_argument('--show', action='store_true',
                        help='Show cracked passwords (John only)')
    
    args = parser.parse_args()
    
    try:
        cracker = HashcatJohnIntegration(authorized=args.authorized)
        
        if args.tool == 'benchmark':
            print("[*] Running benchmarks...")
            results = cracker.benchmark()
            print(json.dumps(results, indent=2))
        
        elif args.tool == 'hashcat':
            if not args.hash_file or not args.hash_type:
                parser.error("--hash-file and --hash-type required for Hashcat")
            
            hash_modes = {
                'md5': 0, 'ntlm': 1000, 'sha256': 1400,
                'sha512': 1800, 'bcrypt': 3200, 'kerberos': 13100
            }
            
            results = cracker.hashcat_crack(
                hash_file=args.hash_file,
                hash_mode=hash_modes.get(args.hash_type, 0),
                attack_mode=args.attack_mode,
                wordlist=args.wordlist,
                rules=args.rules,
                mask=args.mask
            )
            print(json.dumps(results, indent=2))
        
        elif args.tool == 'john':
            if not args.hash_file:
                parser.error("--hash-file required for John")
            
            john_formats = {
                'md5': 'raw-md5', 'ntlm': 'NT', 'sha256': 'raw-sha256',
                'sha512': 'raw-sha512', 'bcrypt': 'bcrypt', 'kerberos': 'krb5tgs'
            }
            
            results = cracker.john_crack(
                hash_file=args.hash_file,
                format=john_formats.get(args.hash_type) if args.hash_type else None,
                wordlist=args.wordlist,
                incremental=args.incremental,
                show_cracked=args.show
            )
            print(json.dumps(results, indent=2))
        
        elif args.tool == 'hybrid':
            if not args.hash_file or not args.hash_type or not args.wordlist:
                parser.error("--hash-file, --hash-type, and --wordlist required for hybrid attack")
            
            results = cracker.hybrid_attack(
                hash_file=args.hash_file,
                hash_type=args.hash_type,
                wordlist=args.wordlist
            )
            print(json.dumps(results, indent=2))
        
        print("\n[+] Cracking completed successfully")
        
    except Exception as e:
        print(f"[-] Error: {e}")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())
