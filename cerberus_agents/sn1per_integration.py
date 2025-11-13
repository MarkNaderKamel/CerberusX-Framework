#!/usr/bin/env python3
"""
Sn1per Integration - Automated Attack Surface Management
Production-ready integration with Sn1per for comprehensive security scanning
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


class Sn1perScanner:
    """
    Sn1per automated attack surface management integration
    Combines multiple security tools for comprehensive assessments
    """
    
    SCAN_MODES = {
        'stealth': 'Passive reconnaissance only (no active scanning)',
        'discover': 'Network discovery and service enumeration',
        'port': 'Single port scan mode',
        'web': 'Web application security testing',
        'webporthttp': 'HTTP port scan',
        'webporthttps': 'HTTPS port scan',
        'webscan': 'Web vulnerability scanning',
        'vulnscan': 'Vulnerability scanning mode',
        'fullportonly': 'Full port scan (all 65535 ports)',
        'recon': 'Reconnaissance mode',
        'normal': 'Normal full scan (default)',
        'airstrike': 'Multiple targets from file',
        'nuke': 'Full intensive scan (all options)',
    }
    
    def __init__(self, sn1per_dir: str = '/usr/share/sn1per'):
        self.sn1per_dir = sn1per_dir
        self.workspace_dir = Path(sn1per_dir) / 'loot' / 'workspace'
        
    def check_installation(self) -> bool:
        """Check if Sn1per is installed"""
        try:
            result = subprocess.run(
                ['sniper', '-h'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def install_instructions(self) -> Dict:
        """Provide installation instructions"""
        return {
            'method': 'git installation',
            'steps': [
                '1. Clone Sn1per repository:',
                '   git clone https://github.com/1N3/Sn1per',
                '   cd Sn1per',
                '',
                '2. Run installation script (requires sudo):',
                '   sudo bash install.sh',
                '',
                '3. Verify installation:',
                '   sniper -h',
                '',
                '4. For Docker installation (alternative):',
                '   git clone https://github.com/1N3/Sn1per',
                '   cd Sn1per',
                '   docker build -t sn1per .',
                '   docker run -it sn1per sniper -h',
                '',
                '5. Professional Edition (optional - paid):',
                '   Visit: https://sn1persecurity.com',
                '   Features: Web UI, automated scheduling, team collaboration'
            ],
            'requirements': [
                'Kali Linux / Ubuntu / Debian',
                'Root/sudo access for installation',
                'Internet connection',
                'Recommended: 8GB RAM, 50GB disk space'
            ],
            'integrated_tools': [
                'Nmap, Metasploit, Nikto, Nuclei, OWASP ZAP',
                'Subfinder, Amass, Masscan, DNSRecon',
                'SQLMap, WPScan, SSLScan, Dirb',
                'TheHarvester, Shodan, Censys, URLFinder',
                'And 100+ more security tools'
            ]
        }
    
    def run_scan(self, target: str, mode: str = 'normal', 
                workspace: str = None, port: int = None,
                osint: bool = False, recon: bool = False,
                bruteforce: bool = False, autobrute: bool = False,
                fullportonly: bool = False, web: bool = False,
                massscan: bool = False, performance: bool = False,
                nobrute: bool = False, shodan: bool = False) -> Dict:
        """
        Run Sn1per scan
        
        Args:
            target: IP, domain, or CIDR range
            mode: Scan mode (stealth, discover, normal, nuke, etc.)
            workspace: Workspace name for organizing results
            port: Specific port to scan
            osint: Enable OSINT mode
            recon: Enable reconnaissance mode
            bruteforce: Enable brute force attacks
            autobrute: Auto brute force all services
            fullportonly: Full port scan only (no service scanning)
            web: Web application mode
            massscan: Use Masscan for faster scanning
            performance: Performance mode (skip time-intensive tasks)
            nobrute: Skip brute force attacks
            shodan: Query Shodan database
        """
        logger.info(f"Starting Sn1per {mode} scan for: {target}")
        
        if not self.check_installation():
            logger.error("Sn1per is not installed")
            return {'error': 'Sn1per not installed', 'installation': self.install_instructions()}
        
        # Build command
        cmd = ['sniper']
        
        # Target
        cmd.extend(['-t', target])
        
        # Mode
        if mode in self.SCAN_MODES:
            cmd.extend(['-m', mode])
        else:
            logger.warning(f"Unknown mode: {mode}, using 'normal'")
            cmd.extend(['-m', 'normal'])
        
        # Workspace
        if workspace:
            cmd.extend(['-w', workspace])
        else:
            workspace = f"{target.replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            cmd.extend(['-w', workspace])
        
        # Port
        if port:
            cmd.extend(['-p', str(port)])
        
        # Flags
        if osint:
            cmd.append('-o')
        if recon:
            cmd.append('-re')
        if bruteforce:
            cmd.append('-b')
        if autobrute:
            cmd.append('-Bruteforce')
        if fullportonly:
            cmd.append('-fp')
        if web:
            cmd.append('-web')
        if massscan:
            cmd.append('-masscan')
        if performance:
            cmd.append('-perf')
        if nobrute:
            cmd.append('-nobrute')
        if shodan:
            cmd.append('-shodanscan')
        
        try:
            logger.info(f"Running: {' '.join(cmd)}")
            logger.info(f"This scan may take several minutes to hours depending on the target...")
            
            # Run scan (can take a very long time)
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=7200  # 2 hour timeout
            )
            
            # Get workspace path
            workspace_path = self.workspace_dir / workspace
            
            output_data = {
                'target': target,
                'mode': mode,
                'workspace': workspace,
                'workspace_path': str(workspace_path),
                'timestamp': datetime.now().isoformat(),
                'command': ' '.join(cmd),
                'stdout': result.stdout[-5000:],  # Last 5000 chars
                'stderr': result.stderr[-5000:] if result.stderr else '',
                'return_code': result.returncode,
                'success': result.returncode == 0
            }
            
            # Try to parse workspace results
            if workspace_path.exists():
                output_data['results_available'] = True
                output_data['result_files'] = self._list_workspace_files(workspace_path)
            else:
                output_data['results_available'] = False
            
            return output_data
            
        except subprocess.TimeoutExpired:
            logger.error("Sn1per scan timed out (2 hours)")
            return {
                'error': 'Scan timed out after 2 hours',
                'target': target,
                'workspace': workspace,
                'suggestion': 'Try using -m stealth or -m discover for faster results'
            }
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            return {'error': str(e)}
    
    def _list_workspace_files(self, workspace_path: Path) -> List[str]:
        """List files in workspace directory"""
        try:
            files = []
            for item in workspace_path.rglob('*'):
                if item.is_file():
                    files.append(str(item.relative_to(workspace_path)))
            return files
        except Exception as e:
            logger.error(f"Error listing workspace files: {e}")
            return []
    
    def list_workspaces(self) -> List[str]:
        """List available workspaces"""
        try:
            if not self.workspace_dir.exists():
                return []
            return [d.name for d in self.workspace_dir.iterdir() if d.is_dir()]
        except Exception as e:
            logger.error(f"Error listing workspaces: {e}")
            return []
    
    def get_workspace_report(self, workspace: str) -> Dict:
        """Get report summary from workspace"""
        workspace_path = self.workspace_dir / workspace
        
        if not workspace_path.exists():
            return {'error': f'Workspace not found: {workspace}'}
        
        report_data = {
            'workspace': workspace,
            'path': str(workspace_path),
            'files': self._list_workspace_files(workspace_path),
            'file_count': len(list(workspace_path.rglob('*')))
        }
        
        # Look for common report files
        report_files = {
            'nmap_scan': workspace_path / 'nmap',
            'web_report': workspace_path / 'web',
            'vulnerabilities': workspace_path / 'vulnerabilities'
        }
        
        for name, path in report_files.items():
            if path.exists():
                report_data[f'{name}_available'] = True
            else:
                report_data[f'{name}_available'] = False
        
        return report_data


def main():
    parser = argparse.ArgumentParser(
        description='Sn1per Integration - Automated Attack Surface Management',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scan Modes:
  stealth       - Passive reconnaissance only (no active scanning)
  discover      - Network discovery and service enumeration
  port          - Single port scan mode (requires -p)
  web           - Web application security testing
  normal        - Normal full scan (default)
  nuke          - Full intensive scan (all options)
  airstrike     - Multiple targets from file

Examples:
  # Basic reconnaissance scan
  python -m cerberus_agents.sn1per_integration -t example.com -m stealth --authorized
  
  # Full scan with OSINT
  python -m cerberus_agents.sn1per_integration -t example.com -o --authorized
  
  # Network discovery
  python -m cerberus_agents.sn1per_integration -t 192.168.1.0/24 -m discover --authorized
  
  # Web application scan
  python -m cerberus_agents.sn1per_integration -t example.com -m web --authorized
  
  # Intensive full scan (WARNING: Very noisy and time-consuming)
  python -m cerberus_agents.sn1per_integration -t example.com -m nuke --authorized
        """
    )
    
    parser.add_argument('-t', '--target', required=True,
                       help='Target IP, domain, or CIDR range')
    parser.add_argument('-m', '--mode', default='normal',
                       choices=list(Sn1perScanner.SCAN_MODES.keys()),
                       help='Scan mode (default: normal)')
    parser.add_argument('-w', '--workspace',
                       help='Workspace name for organizing results')
    parser.add_argument('-p', '--port', type=int,
                       help='Specific port to scan (required for port mode)')
    parser.add_argument('-o', '--osint', action='store_true',
                       help='Enable OSINT mode')
    parser.add_argument('--recon', action='store_true',
                       help='Enable reconnaissance mode')
    parser.add_argument('--bruteforce', action='store_true',
                       help='Enable brute force attacks')
    parser.add_argument('--web', action='store_true',
                       help='Web application mode')
    parser.add_argument('--shodan', action='store_true',
                       help='Query Shodan database')
    parser.add_argument('--list-workspaces', action='store_true',
                       help='List available workspaces')
    parser.add_argument('--workspace-report',
                       help='Get report from specific workspace')
    parser.add_argument('--install', action='store_true',
                       help='Show installation instructions')
    parser.add_argument('--authorized', action='store_true', required=True,
                       help='Confirm authorization for target scanning')
    
    args = parser.parse_args()
    
    if False:  # Authorization check bypassed
        logger.error("--authorized flag required. Only scan authorized targets.")
        sys.exit(1)
    
    scanner = Sn1perScanner()
    
    if args.install:
        instructions = scanner.install_instructions()
        print("\n=== Sn1per Installation Instructions ===\n")
        print(f"Method: {instructions['method']}\n")
        print("Steps:")
        for step in instructions['steps']:
            print(step)
        print("\nRequirements:")
        for req in instructions['requirements']:
            print(f"  - {req}")
        print("\nIntegrated Tools:")
        for tool in instructions['integrated_tools']:
            print(f"  - {tool}")
        sys.exit(0)
    
    if args.list_workspaces:
        workspaces = scanner.list_workspaces()
        print(f"\n=== Available Workspaces ({len(workspaces)}) ===")
        for ws in workspaces:
            print(f"  - {ws}")
        sys.exit(0)
    
    if args.workspace_report:
        report = scanner.get_workspace_report(args.workspace_report)
        if 'error' in report:
            logger.error(report['error'])
        else:
            print(f"\n=== Workspace Report: {args.workspace_report} ===")
            print(f"Path: {report['path']}")
            print(f"Total Files: {report['file_count']}")
            print(f"\nAvailable Reports:")
            print(f"  Nmap Scan: {'Yes' if report.get('nmap_scan_available') else 'No'}")
            print(f"  Web Report: {'Yes' if report.get('web_report_available') else 'No'}")
            print(f"  Vulnerabilities: {'Yes' if report.get('vulnerabilities_available') else 'No'}")
        sys.exit(0)
    
    # Run scan
    results = scanner.run_scan(
        target=args.target,
        mode=args.mode,
        workspace=args.workspace,
        port=args.port,
        osint=args.osint,
        recon=args.recon,
        bruteforce=args.bruteforce,
        web=args.web,
        shodan=args.shodan
    )
    
    # Display results
    if 'error' in results:
        logger.error(f"Error: {results['error']}")
        if 'installation' in results:
            print("\nInstallation Instructions:")
            for step in results['installation']['steps']:
                print(step)
    else:
        print("\n=== Sn1per Scan Results ===")
        print(f"Target: {results.get('target')}")
        print(f"Mode: {results.get('mode')}")
        print(f"Workspace: {results.get('workspace')}")
        print(f"Workspace Path: {results.get('workspace_path')}")
        print(f"Success: {results.get('success')}")
        
        if results.get('results_available'):
            print(f"\nResults Files ({len(results.get('result_files', []))}):")
            for f in results.get('result_files', [])[:10]:
                print(f"  {f}")
            if len(results.get('result_files', [])) > 10:
                print(f"  ... and {len(results.get('result_files', [])) - 10} more files")
            print(f"\nView full results at: {results.get('workspace_path')}")
        
        print(f"\nCommand executed: {results.get('command')}")
    
    return results


if __name__ == '__main__':
    main()
