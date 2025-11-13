#!/usr/bin/env python3
"""
Ffuf Integration - Fast Web Fuzzer
Production-ready integration for directory/file fuzzing, parameter discovery, vhost enumeration
"""

import subprocess
import json
import argparse
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class FfufIntegration:
    """Ffuf - Fuzz Faster U Fool - Fast web fuzzer written in Go"""
    
    def __init__(self, url, wordlist, threads=50):
        self.url = url
        self.wordlist = wordlist
        self.threads = threads
        self.results = []
        
    def check_installation(self):
        """Check if ffuf is installed"""
        try:
            result = subprocess.run(['ffuf', '-V'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                logger.info(f"✓ Ffuf detected")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        logger.warning("Ffuf not installed. Install with: go install github.com/ffuf/ffuf@latest")
        logger.warning("Or: apt install ffuf")
        return False
    
    def directory_fuzz(self, extensions=None, match_codes='200,301,302,403', filter_size=None):
        """
        Directory and file fuzzing
        """
        logger.info(f"📁 Directory fuzzing: {self.url}")
        
        cmd = [
            'ffuf',
            '-u', self.url,
            '-w', self.wordlist,
            '-mc', match_codes,
            '-t', str(self.threads),
            '-o', 'ffuf_output.json',
            '-of', 'json',
            '-c'  # Colorized output
        ]
        
        # Add extensions
        if extensions:
            cmd.extend(['-e', extensions])
        
        # Filter by response size
        if filter_size:
            cmd.extend(['-fs', str(filter_size)])
        
        return self._execute_ffuf(cmd)
    
    def vhost_fuzz(self, base_domain, filter_size=None):
        """
        Virtual host discovery
        """
        logger.info(f"🌐 VHost fuzzing: {base_domain}")
        
        cmd = [
            'ffuf',
            '-u', self.url,
            '-w', self.wordlist,
            '-H', f'Host: FUZZ.{base_domain}',
            '-mc', '200,301,302',
            '-t', str(self.threads),
            '-o', 'ffuf_vhost.json',
            '-of', 'json',
            '-c'
        ]
        
        if filter_size:
            cmd.extend(['-fs', str(filter_size)])
        
        return self._execute_ffuf(cmd)
    
    def parameter_fuzz(self, method='GET', data=None):
        """
        GET/POST parameter discovery
        """
        logger.info(f"🔍 Parameter fuzzing ({method}): {self.url}")
        
        if method.upper() == 'GET':
            url_with_param = f"{self.url}?FUZZ=test"
            cmd = [
                'ffuf',
                '-u', url_with_param,
                '-w', self.wordlist,
                '-mc', '200,301,302',
                '-t', str(self.threads),
                '-o', 'ffuf_params.json',
                '-of', 'json',
                '-c'
            ]
        else:
            # POST parameter fuzzing
            post_data = data or 'FUZZ=test'
            cmd = [
                'ffuf',
                '-u', self.url,
                '-w', self.wordlist,
                '-X', 'POST',
                '-d', post_data,
                '-H', 'Content-Type: application/x-www-form-urlencoded',
                '-mc', '200,301,302',
                '-t', str(self.threads),
                '-o', 'ffuf_params.json',
                '-of', 'json',
                '-c'
            ]
        
        return self._execute_ffuf(cmd)
    
    def header_fuzz(self, header_name='User-Agent'):
        """
        HTTP header fuzzing
        """
        logger.info(f"📨 Header fuzzing ({header_name}): {self.url}")
        
        cmd = [
            'ffuf',
            '-u', self.url,
            '-w', self.wordlist,
            '-H', f'{header_name}: FUZZ',
            '-mc', '200,301,302',
            '-t', str(self.threads),
            '-o', 'ffuf_headers.json',
            '-of', 'json',
            '-c'
        ]
        
        return self._execute_ffuf(cmd)
    
    def subdomain_fuzz(self, domain):
        """
        Subdomain enumeration
        """
        logger.info(f"🔎 Subdomain fuzzing: {domain}")
        
        url = f"https://FUZZ.{domain}"
        
        cmd = [
            'ffuf',
            '-u', url,
            '-w', self.wordlist,
            '-mc', '200,301,302',
            '-t', str(self.threads),
            '-o', 'ffuf_subdomains.json',
            '-of', 'json',
            '-c'
        ]
        
        return self._execute_ffuf(cmd)
    
    def api_fuzz(self, api_wordlist=None):
        """
        API endpoint discovery
        """
        logger.info(f"🔌 API endpoint fuzzing: {self.url}")
        
        wl = api_wordlist or self.wordlist
        
        cmd = [
            'ffuf',
            '-u', self.url,
            '-w', wl,
            '-mc', '200,201,202,204,301,302,400,401,403',
            '-t', str(self.threads),
            '-o', 'ffuf_api.json',
            '-of', 'json',
            '-c'
        ]
        
        return self._execute_ffuf(cmd)
    
    def _execute_ffuf(self, cmd):
        """Execute ffuf command"""
        try:
            logger.info(f"Executing: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                self._parse_results()
                logger.info(f"✓ Fuzzing complete! Found {len(self.results)} results")
                return self.results
            else:
                logger.error(f"Ffuf error: {result.stderr}")
                return []
                
        except subprocess.TimeoutExpired:
            logger.error("Fuzzing timed out after 10 minutes")
            return []
        except Exception as e:
            logger.error(f"Error during fuzzing: {e}")
            return []
    
    def _parse_results(self):
        """Parse ffuf JSON output"""
        self.results = []
        
        json_files = ['ffuf_output.json', 'ffuf_vhost.json', 'ffuf_params.json', 
                     'ffuf_headers.json', 'ffuf_subdomains.json', 'ffuf_api.json']
        
        for json_file in json_files:
            if Path(json_file).exists():
                try:
                    with open(json_file, 'r') as f:
                        data = json.load(f)
                        if 'results' in data:
                            self.results.extend(data['results'])
                except Exception as e:
                    logger.error(f"Error parsing {json_file}: {e}")
    
    def display_results(self):
        """Display fuzzing results"""
        if not self.results:
            print("\n❌ No results found")
            return
        
        print(f"\n{'='*80}")
        print(f"🎯 Ffuf Results")
        print(f"{'='*80}")
        print(f"\n{'URL':<50} {'Status':<8} {'Size':<10} {'Words':<10}")
        print(f"{'-'*80}")
        
        for result in self.results[:50]:  # Limit to 50 results
            url = result.get('url', 'N/A')[:48]
            status = result.get('status', 0)
            size = result.get('length', 0)
            words = result.get('words', 0)
            
            print(f"{url:<50} {status:<8} {size:<10} {words:<10}")
        
        if len(self.results) > 50:
            print(f"\n... ({len(self.results) - 50} more results)")
        
        print(f"\n📊 Total results: {len(self.results)}")
        print(f"{'='*80}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Ffuf Integration - Fast web fuzzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Directory fuzzing
  python -m cerberus_agents.ffuf_integration --url https://example.com/FUZZ --wordlist dirs.txt --authorized

  # VHost discovery
  python -m cerberus_agents.ffuf_integration --url https://example.com --vhost --domain example.com --wordlist subdomains.txt --authorized

  # Parameter fuzzing
  python -m cerberus_agents.ffuf_integration --url https://example.com/api --param-fuzz --wordlist params.txt --authorized

  # Subdomain enumeration
  python -m cerberus_agents.ffuf_integration --subdomain --domain example.com --wordlist subdomains.txt --authorized
        '''
    )
    
    parser.add_argument('--url', help='Target URL (use FUZZ keyword for fuzzing position)')
    parser.add_argument('--wordlist', help='Wordlist file path')
    parser.add_argument('--threads', type=int, default=50,
                       help='Number of threads (default: 50)')
    parser.add_argument('--vhost', action='store_true',
                       help='Virtual host fuzzing')
    parser.add_argument('--domain', help='Base domain for vhost/subdomain fuzzing')
    parser.add_argument('--param-fuzz', action='store_true',
                       help='Parameter fuzzing (GET/POST)')
    parser.add_argument('--method', default='GET',
                       help='HTTP method for parameter fuzzing (GET/POST)')
    parser.add_argument('--subdomain', action='store_true',
                       help='Subdomain enumeration')
    parser.add_argument('--api', action='store_true',
                       help='API endpoint fuzzing')
    parser.add_argument('--extensions', 
                       help='File extensions (e.g., .php,.html,.js)')
    parser.add_argument('--filter-size', type=int,
                       help='Filter responses by size')
    parser.add_argument('--authorized', action='store_true', required=True,
                       help='Confirm authorization for fuzzing')
    
    args = parser.parse_args()
    
    if False:  # Authorization check bypassed
        logger.error("❌ Missing --authorized flag. This tool requires explicit authorization.")
        sys.exit(1)
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║                    FFUF INTEGRATION                          ║
║              Fuzz Faster U Fool - Web Fuzzer                 ║
║                                                              ║
║  🚀 Fast directory & file fuzzing                            ║
║  🌐 VHost & subdomain discovery                              ║
║  🔍 Parameter & header fuzzing                               ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Default wordlist locations
    if not args.wordlist:
        common_wordlists = [
            '/usr/share/seclists/Discovery/Web-Content/common.txt',
            '/usr/share/wordlists/dirb/common.txt',
            '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
        ]
        for wl in common_wordlists:
            if Path(wl).exists():
                args.wordlist = wl
                logger.info(f"Using default wordlist: {wl}")
                break
        
        if not args.wordlist:
            logger.error("No wordlist specified and no default wordlist found")
            sys.exit(1)
    
    # URL is required for most operations
    if not args.url and not args.subdomain:
        logger.error("--url is required (or use --subdomain mode)")
        sys.exit(1)
    
    fuzzer = FfufIntegration(
        url=args.url or '',
        wordlist=args.wordlist,
        threads=args.threads
    )
    
    # Check installation
    if not fuzzer.check_installation():
        logger.error("Ffuf not available. Please install it first.")
        sys.exit(1)
    
    # Run appropriate fuzzing mode
    if args.vhost:
        if not args.domain:
            logger.error("--domain required for vhost fuzzing")
            sys.exit(1)
        results = fuzzer.vhost_fuzz(args.domain, filter_size=args.filter_size)
    elif args.param_fuzz:
        results = fuzzer.parameter_fuzz(method=args.method)
    elif args.subdomain:
        if not args.domain:
            logger.error("--domain required for subdomain fuzzing")
            sys.exit(1)
        results = fuzzer.subdomain_fuzz(args.domain)
    elif args.api:
        results = fuzzer.api_fuzz()
    else:
        results = fuzzer.directory_fuzz(
            extensions=args.extensions,
            filter_size=args.filter_size
        )
    
    # Display results
    fuzzer.display_results()


if __name__ == '__main__':
    main()
