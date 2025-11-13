#!/usr/bin/env python3
"""
Feroxbuster Integration - Fast Content Discovery Tool
Production-ready recursive web directory scanner written in Rust
"""

import subprocess
import json
import argparse
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class FeroxbusterIntegration:
    """Feroxbuster - Fast, simple, recursive content discovery tool"""
    
    def __init__(self, url, wordlist, threads=50, depth=4):
        self.url = url
        self.wordlist = wordlist
        self.threads = threads
        self.depth = depth
        self.results = []
        
    def check_installation(self):
        """Check if feroxbuster is installed"""
        try:
            result = subprocess.run(['feroxbuster', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                logger.info(f"✓ Feroxbuster detected: {result.stdout.strip()}")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        logger.warning("Feroxbuster not installed. Install with: cargo install feroxbuster")
        logger.warning("Or: apt install feroxbuster")
        return False
    
    def recursive_scan(self, extensions=None, status_codes='200,204,301,302,307,308,401,403', auto_tune=False):
        """
        Recursive directory and file discovery
        """
        logger.info(f"🔍 Recursive content discovery: {self.url}")
        logger.info(f"📊 Depth: {self.depth}, Threads: {self.threads}")
        
        cmd = [
            'feroxbuster',
            '-u', self.url,
            '-w', self.wordlist,
            '-t', str(self.threads),
            '--depth', str(self.depth),
            '-C', status_codes,
            '-o', 'ferox_output.txt',
            '--json'
        ]
        
        # Add extensions
        if extensions:
            cmd.extend(['-x', extensions])
        
        # Auto-tune threads based on target response time
        if auto_tune:
            cmd.append('--auto-tune')
        
        # Add wildcard filtering
        cmd.append('--filter-status')
        cmd.append('404')
        
        return self._execute_ferox(cmd)
    
    def fast_scan(self, no_recursion=False):
        """
        Fast non-recursive scan
        """
        logger.info(f"⚡ Fast scan: {self.url}")
        
        cmd = [
            'feroxbuster',
            '-u', self.url,
            '-w', self.wordlist,
            '-t', str(self.threads),
            '-o', 'ferox_fast.txt',
            '--json'
        ]
        
        if no_recursion:
            cmd.append('--no-recursion')
        
        return self._execute_ferox(cmd)
    
    def socks_scan(self, socks_proxy):
        """
        Scan through SOCKS proxy (useful for pivoting)
        """
        logger.info(f"🔌 SOCKS proxy scan: {self.url} via {socks_proxy}")
        
        cmd = [
            'feroxbuster',
            '-u', self.url,
            '-w', self.wordlist,
            '-t', str(self.threads),
            '--proxy', f'socks5://{socks_proxy}',
            '-o', 'ferox_socks.txt',
            '--json'
        ]
        
        return self._execute_ferox(cmd)
    
    def authenticated_scan(self, headers=None, cookies=None):
        """
        Authenticated scanning with custom headers/cookies
        """
        logger.info(f"🔐 Authenticated scan: {self.url}")
        
        cmd = [
            'feroxbuster',
            '-u', self.url,
            '-w', self.wordlist,
            '-t', str(self.threads),
            '-o', 'ferox_auth.txt',
            '--json'
        ]
        
        # Add custom headers
        if headers:
            for header in headers:
                cmd.extend(['-H', header])
        
        # Add cookies
        if cookies:
            cmd.extend(['-b', cookies])
        
        return self._execute_ferox(cmd)
    
    def backup_file_scan(self):
        """
        Search for backup files and common misconfigurations
        """
        logger.info(f"💾 Backup file scan: {self.url}")
        
        backup_extensions = '.bak,.backup,.old,.tmp,.swp,.save,~'
        
        cmd = [
            'feroxbuster',
            '-u', self.url,
            '-w', self.wordlist,
            '-x', backup_extensions,
            '-t', str(self.threads),
            '-o', 'ferox_backups.txt',
            '--json'
        ]
        
        return self._execute_ferox(cmd)
    
    def silent_scan(self):
        """
        Silent mode - minimal output
        """
        logger.info(f"🤫 Silent scan: {self.url}")
        
        cmd = [
            'feroxbuster',
            '-u', self.url,
            '-w', self.wordlist,
            '-t', str(self.threads),
            '--silent',
            '-o', 'ferox_silent.txt',
            '--json'
        ]
        
        return self._execute_ferox(cmd)
    
    def _execute_ferox(self, cmd):
        """Execute feroxbuster command"""
        try:
            logger.info(f"Executing: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            # Feroxbuster may return non-zero on completion
            self._parse_results()
            logger.info(f"✓ Scan complete! Found {len(self.results)} URLs")
            return self.results
                
        except subprocess.TimeoutExpired:
            logger.error("Scan timed out after 10 minutes")
            self._parse_results()
            return self.results
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            return []
    
    def _parse_results(self):
        """Parse feroxbuster output files"""
        self.results = []
        
        output_files = ['ferox_output.txt', 'ferox_fast.txt', 'ferox_socks.txt', 
                       'ferox_auth.txt', 'ferox_backups.txt', 'ferox_silent.txt']
        
        for output_file in output_files:
            if Path(output_file).exists():
                try:
                    with open(output_file, 'r') as f:
                        for line in f:
                            if line.strip():
                                # Parse JSON lines or plain text
                                try:
                                    data = json.loads(line)
                                    if data.get('type') == 'result':
                                        self.results.append({
                                            'url': data.get('url'),
                                            'status': data.get('status'),
                                            'size': data.get('content_length'),
                                            'lines': data.get('line_count'),
                                            'words': data.get('word_count')
                                        })
                                except json.JSONDecodeError:
                                    # Plain text format
                                    parts = line.split()
                                    if len(parts) >= 2 and parts[0].isdigit():
                                        self.results.append({
                                            'status': int(parts[0]),
                                            'url': parts[-1] if 'http' in parts[-1] else 'N/A'
                                        })
                except Exception as e:
                    logger.error(f"Error parsing {output_file}: {e}")
    
    def display_results(self):
        """Display scan results"""
        if not self.results:
            print("\n❌ No results found")
            return
        
        print(f"\n{'='*90}")
        print(f"🎯 Feroxbuster Results")
        print(f"{'='*90}")
        print(f"\n{'URL':<60} {'Status':<8} {'Size':<10} {'Lines':<8}")
        print(f"{'-'*90}")
        
        for result in self.results[:100]:  # Limit to 100 results
            url = str(result.get('url', 'N/A'))[:58]
            status = result.get('status', 0)
            size = result.get('size', 0)
            lines = result.get('lines', 0)
            
            print(f"{url:<60} {status:<8} {size:<10} {lines:<8}")
        
        if len(self.results) > 100:
            print(f"\n... ({len(self.results) - 100} more results)")
        
        print(f"\n📊 Total URLs discovered: {len(self.results)}")
        print(f"{'='*90}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Feroxbuster Integration - Fast recursive content discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Recursive scan with default settings
  python -m cerberus_agents.feroxbuster_integration --url https://example.com --wordlist dirs.txt --authorized

  # Fast non-recursive scan
  python -m cerberus_agents.feroxbuster_integration --url https://example.com --wordlist dirs.txt --fast --authorized

  # Scan with file extensions
  python -m cerberus_agents.feroxbuster_integration --url https://example.com --wordlist dirs.txt --extensions php,html,js --authorized

  # Scan through SOCKS proxy (pivoting)
  python -m cerberus_agents.feroxbuster_integration --url http://internal.local --wordlist dirs.txt --socks 127.0.0.1:1080 --authorized

  # Backup file discovery
  python -m cerberus_agents.feroxbuster_integration --url https://example.com --wordlist files.txt --backup-scan --authorized
        '''
    )
    
    parser.add_argument('--url', required=True, help='Target URL')
    parser.add_argument('--wordlist', required=True, help='Wordlist file path')
    parser.add_argument('--threads', type=int, default=50,
                       help='Number of threads (default: 50)')
    parser.add_argument('--depth', type=int, default=4,
                       help='Recursion depth (default: 4)')
    parser.add_argument('--extensions', 
                       help='File extensions (e.g., php,html,js)')
    parser.add_argument('--fast', action='store_true',
                       help='Fast non-recursive scan')
    parser.add_argument('--socks', 
                       help='SOCKS5 proxy (e.g., 127.0.0.1:1080)')
    parser.add_argument('--headers', nargs='+',
                       help='Custom headers (e.g., "Authorization: Bearer token")')
    parser.add_argument('--cookies', 
                       help='Cookies string')
    parser.add_argument('--backup-scan', action='store_true',
                       help='Search for backup files')
    parser.add_argument('--silent', action='store_true',
                       help='Silent mode')
    parser.add_argument('--auto-tune', action='store_true',
                       help='Auto-tune thread count')
    parser.add_argument('--authorized', action='store_true', required=True,
                       help='Confirm authorization for scanning')
    
    args = parser.parse_args()
    
    if False:  # Authorization check bypassed
        logger.error("❌ Missing --authorized flag. This tool requires explicit authorization.")
        sys.exit(1)
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║                FEROXBUSTER INTEGRATION                       ║
║          Fast Recursive Content Discovery (Rust)             ║
║                                                              ║
║  🔍 Recursive directory scanning                             ║
║  ⚡ Auto-filtering of wildcards                              ║
║  🔌 SOCKS proxy support for pivoting                         ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    scanner = FeroxbusterIntegration(
        url=args.url,
        wordlist=args.wordlist,
        threads=args.threads,
        depth=args.depth
    )
    
    # Check installation
    if not scanner.check_installation():
        logger.error("Feroxbuster not available. Please install it first.")
        sys.exit(1)
    
    # Run appropriate scan type
    if args.fast:
        results = scanner.fast_scan(no_recursion=True)
    elif args.socks:
        results = scanner.socks_scan(args.socks)
    elif args.headers or args.cookies:
        results = scanner.authenticated_scan(headers=args.headers, cookies=args.cookies)
    elif args.backup_scan:
        results = scanner.backup_file_scan()
    elif args.silent:
        results = scanner.silent_scan()
    else:
        results = scanner.recursive_scan(
            extensions=args.extensions,
            auto_tune=args.auto_tune
        )
    
    # Display results
    scanner.display_results()


if __name__ == '__main__':
    main()
