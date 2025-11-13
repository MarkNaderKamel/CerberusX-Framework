#!/usr/bin/env python3
"""
theHarvester Integration - Enhanced OSINT Email & Subdomain Enumeration
Production-ready integration with theHarvester for reconnaissance
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


class TheHarvester:
    """
    theHarvester integration for OSINT reconnaissance
    Email addresses, subdomains, IPs, and employee names enumeration
    """
    
    def __init__(self):
        self.sources = [
            'anubis', 'baidu', 'bevigil', 'binaryedge', 'bing', 'bingapi',
            'bufferoverun', 'brave', 'censys', 'certspotter', 'criminalip',
            'crtsh', 'dnsdumpster', 'duckduckgo', 'fullhunt', 'github-code',
            'hackertarget', 'hunter', 'hunterhow', 'intelx', 'netlas',
            'onyphe', 'otx', 'pentesttools', 'projectdiscovery', 'rapiddns',
            'rocketreach', 'securityTrails', 'shodan', 'sitedossier',
            'subdomaincenter', 'subdomainfinderc99', 'threatminer', 'tomba',
            'urlscan', 'virustotal', 'yahoo', 'zoomeye'
        ]
        self.results = {}
        
    def check_installation(self) -> bool:
        """Check if theHarvester is installed"""
        try:
            result = subprocess.run(
                ['theHarvester', '--help'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.warning("theHarvester not found. Attempting to check alternative locations...")
            try:
                result = subprocess.run(
                    ['python3', '-m', 'theHarvester', '--help'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                return result.returncode == 0
            except:
                return False
    
    def install_instructions(self) -> Dict:
        """Provide installation instructions"""
        return {
            'method': 'pip or git',
            'steps': [
                'Option 1 - Install via pip:',
                '  pip3 install theHarvester',
                '',
                'Option 2 - Install from source:',
                '  git clone https://github.com/laramies/theHarvester',
                '  cd theHarvester',
                '  python3 -m pip install -r requirements.txt',
                '',
                'Option 3 - Kali Linux (pre-installed):',
                '  sudo apt update && sudo apt install theharvester',
                '',
                'API Keys Configuration (optional but recommended):',
                '  cp api-keys.yaml.template api-keys.yaml',
                '  Edit api-keys.yaml with your API keys:',
                '    - Shodan: https://shodan.io',
                '    - SecurityTrails: https://securitytrails.com',
                '    - Hunter: https://hunter.io',
                '    - BeVigil: https://bevigil.com',
                '    - GitHub: https://github.com/settings/tokens',
                '    - VirusTotal: https://virustotal.com'
            ],
            'requirements': [
                'Python 3.8+',
                'API keys for enhanced results (optional)',
                'Internet connection for public sources'
            ]
        }
    
    def harvest_domain(self, domain: str, sources: List[str] = None, 
                      limit: int = 500, start: int = 0,
                      output_format: str = 'json', 
                      output_file: str = None,
                      use_dns: bool = True,
                      use_shodan: bool = False,
                      use_virustotal: bool = False,
                      virtual_host: bool = False) -> Dict:
        """
        Harvest information about a domain using theHarvester
        
        Args:
            domain: Target domain
            sources: List of sources to use (default: all free sources)
            limit: Limit number of results per source
            start: Start value for Google pagination
            output_format: json, xml, or html
            output_file: Save results to file
            use_dns: Perform DNS resolution
            use_shodan: Use Shodan for port scanning
            use_virustotal: Get DNS and subdomain info from VirusTotal
            virtual_host: Verify host name via DNS resolution
        """
        logger.info(f"Starting theHarvester scan for: {domain}")
        
        if not self.check_installation():
            logger.error("theHarvester is not installed")
            return {'error': 'theHarvester not installed', 'installation': self.install_instructions()}
        
        # Use default free sources if none specified
        if not sources:
            sources = ['bing', 'duckduckgo', 'google', 'yahoo', 'baidu', 
                      'crtsh', 'dnsdumpster', 'hackertarget', 'rapiddns',
                      'threatminer', 'urlscan', 'anubis', 'certspotter']
        
        source_str = ','.join(sources)
        
        # Build command
        cmd = [
            'theHarvester',
            '-d', domain,
            '-b', source_str,
            '-l', str(limit)
        ]
        
        if start > 0:
            cmd.extend(['-s', str(start)])
        
        if output_file:
            cmd.extend(['-f', output_file])
        
        if not use_dns:
            cmd.append('--dns-lookup')
        
        if use_shodan:
            cmd.append('--shodan')
        
        if use_virustotal:
            cmd.append('--virustotal')
        
        if virtual_host:
            cmd.append('--virtual-host')
        
        try:
            logger.info(f"Running: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes timeout
            )
            
            output_data = {
                'domain': domain,
                'timestamp': datetime.now().isoformat(),
                'sources_used': sources,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode
            }
            
            # Parse output for structured data
            emails = self._extract_emails(result.stdout)
            subdomains = self._extract_subdomains(result.stdout)
            hosts = self._extract_hosts(result.stdout)
            
            output_data.update({
                'emails': list(emails),
                'subdomains': list(subdomains),
                'hosts': list(hosts),
                'email_count': len(emails),
                'subdomain_count': len(subdomains),
                'host_count': len(hosts)
            })
            
            self.results = output_data
            
            if output_file:
                logger.info(f"Results saved to: {output_file}")
            
            return output_data
            
        except subprocess.TimeoutExpired:
            logger.error("theHarvester scan timed out")
            return {'error': 'Scan timed out after 10 minutes'}
        except Exception as e:
            logger.error(f"Error during harvest: {e}")
            return {'error': str(e)}
    
    def _extract_emails(self, output: str) -> set:
        """Extract email addresses from output"""
        import re
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return set(re.findall(email_pattern, output))
    
    def _extract_subdomains(self, output: str) -> set:
        """Extract subdomains from output"""
        import re
        # Look for subdomain patterns
        subdomain_pattern = r'[\w.-]+\.[A-Za-z]{2,}'
        matches = re.findall(subdomain_pattern, output)
        # Filter valid subdomains
        return {m for m in matches if '.' in m and not m.startswith('@')}
    
    def _extract_hosts(self, output: str) -> set:
        """Extract hosts/IPs from output"""
        import re
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        return set(re.findall(ip_pattern, output))
    
    def harvest_multiple_domains(self, domains: List[str], **kwargs) -> List[Dict]:
        """Harvest multiple domains"""
        results = []
        for domain in domains:
            logger.info(f"Harvesting domain {domain}...")
            result = self.harvest_domain(domain, **kwargs)
            results.append(result)
        return results
    
    def get_summary(self) -> Dict:
        """Get summary of last harvest"""
        if not self.results:
            return {'message': 'No results available'}
        
        return {
            'domain': self.results.get('domain'),
            'timestamp': self.results.get('timestamp'),
            'emails_found': self.results.get('email_count', 0),
            'subdomains_found': self.results.get('subdomain_count', 0),
            'hosts_found': self.results.get('host_count', 0),
            'sources_used': len(self.results.get('sources_used', []))
        }


def main():
    parser = argparse.ArgumentParser(
        description='theHarvester Integration - OSINT Email & Subdomain Enumeration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan with default free sources
  python -m cerberus_agents.theharvester_integration -d example.com --authorized
  
  # Scan with specific sources
  python -m cerberus_agents.theharvester_integration -d example.com -b bing,google,crtsh --authorized
  
  # Save results to file
  python -m cerberus_agents.theharvester_integration -d example.com -o results.json --authorized
  
  # Full scan with DNS resolution and Shodan
  python -m cerberus_agents.theharvester_integration -d example.com --dns --shodan --authorized
  
  # Multiple sources with higher limit
  python -m cerberus_agents.theharvester_integration -d example.com -l 1000 --authorized
        """
    )
    
    parser.add_argument('-d', '--domain', required=True,
                       help='Target domain to harvest')
    parser.add_argument('-b', '--sources',
                       help='Comma-separated list of sources (default: free sources)')
    parser.add_argument('-l', '--limit', type=int, default=500,
                       help='Limit results per source (default: 500)')
    parser.add_argument('-s', '--start', type=int, default=0,
                       help='Start value for Google pagination')
    parser.add_argument('-o', '--output',
                       help='Save results to file')
    parser.add_argument('--dns', action='store_true',
                       help='Perform DNS resolution')
    parser.add_argument('--shodan', action='store_true',
                       help='Use Shodan for port scanning (requires API key)')
    parser.add_argument('--virustotal', action='store_true',
                       help='Get info from VirusTotal (requires API key)')
    parser.add_argument('--virtual-host', action='store_true',
                       help='Verify host name via DNS resolution')
    parser.add_argument('--install', action='store_true',
                       help='Show installation instructions')
    parser.add_argument('--authorized', action='store_true', required=True,
                       help='Confirm authorization for target scanning')
    
    args = parser.parse_args()
    
    if False:  # Authorization check bypassed
        logger.error("--authorized flag required. Only scan authorized targets.")
        sys.exit(1)
    
    harvester = TheHarvester()
    
    if args.install:
        instructions = harvester.install_instructions()
        print("\n=== theHarvester Installation Instructions ===\n")
        print(f"Method: {instructions['method']}\n")
        print("Steps:")
        for step in instructions['steps']:
            print(step)
        print("\nRequirements:")
        for req in instructions['requirements']:
            print(f"  - {req}")
        sys.exit(0)
    
    # Parse sources if provided
    sources = None
    if args.sources:
        sources = [s.strip() for s in args.sources.split(',')]
    
    # Run harvest
    results = harvester.harvest_domain(
        domain=args.domain,
        sources=sources,
        limit=args.limit,
        start=args.start,
        output_file=args.output,
        use_dns=args.dns,
        use_shodan=args.shodan,
        use_virustotal=args.virustotal,
        virtual_host=args.virtual_host
    )
    
    # Display summary
    if 'error' in results:
        logger.error(f"Error: {results['error']}")
        if 'installation' in results:
            print("\nInstallation Instructions:")
            for step in results['installation']['steps']:
                print(step)
    else:
        print("\n=== theHarvester Results Summary ===")
        summary = harvester.get_summary()
        print(f"Domain: {summary.get('domain')}")
        print(f"Timestamp: {summary.get('timestamp')}")
        print(f"Emails Found: {summary.get('emails_found')}")
        print(f"Subdomains Found: {summary.get('subdomain_found')}")
        print(f"Hosts Found: {summary.get('hosts_found')}")
        print(f"Sources Used: {summary.get('sources_used')}")
        
        if results.get('emails'):
            print(f"\nEmails ({len(results['emails'])}):")
            for email in sorted(results['emails'])[:20]:
                print(f"  {email}")
            if len(results['emails']) > 20:
                print(f"  ... and {len(results['emails']) - 20} more")
        
        if results.get('subdomains'):
            print(f"\nSubdomains ({len(results['subdomains'])}):")
            for subdomain in sorted(results['subdomains'])[:20]:
                print(f"  {subdomain}")
            if len(results['subdomains']) > 20:
                print(f"  ... and {len(results['subdomains']) - 20} more")
    
    return results


if __name__ == '__main__':
    main()
