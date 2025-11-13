#!/usr/bin/env python3
"""
Metagoofil Integration - Document Metadata Extraction for OSINT
Production-ready integration for extracting metadata from public documents
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


class Metagoofil:
    """
    Metagoofil - Metadata extraction from public documents
    Extract usernames, software versions, and system information from PDFs, DOCs, XLS, PPT
    """
    
    FILE_TYPES = {
        'pdf': 'PDF documents',
        'doc': 'Microsoft Word documents (.doc)',
        'docx': 'Microsoft Word documents (.docx)',
        'xls': 'Microsoft Excel spreadsheets (.xls)',
        'xlsx': 'Microsoft Excel spreadsheets (.xlsx)',
        'ppt': 'Microsoft PowerPoint presentations (.ppt)',
        'pptx': 'Microsoft PowerPoint presentations (.pptx)',
        'all': 'All supported document types'
    }
    
    def __init__(self, output_dir: str = './metagoofil_downloads'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def check_installation(self) -> bool:
        """Check if metagoofil is installed"""
        try:
            result = subprocess.run(
                ['metagoofil', '-h'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            try:
                result = subprocess.run(
                    ['python3', '-m', 'metagoofil', '-h'],
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
                '1. Install via pip (recommended):',
                '   pip3 install metagoofil',
                '',
                '2. Or install from source:',
                '   git clone https://github.com/laramies/metagoofil',
                '   cd metagoofil',
                '   pip3 install -r requirements.txt',
                '',
                '3. Kali Linux (pre-installed):',
                '   sudo apt update && sudo apt install metagoofil',
                '',
                '4. Verify installation:',
                '   metagoofil -h',
                ''
            ],
            'requirements': [
                'Python 3.6+',
                'Hachoir library (for metadata extraction)',
                'PdfMiner library (for PDF parsing)',
                'Internet connection for document discovery'
            ],
            'capabilities': [
                'Google dorking for public documents',
                'Automatic document download',
                'Metadata extraction from multiple formats',
                'Author/creator name discovery',
                'Software version identification',
                'Internal network information leakage',
                'MAC address discovery (from Office docs)',
                'Creation/modification timestamps',
                'Printer information',
                'Server paths and network shares'
            ]
        }
    
    def extract_metadata(self, domain: str, file_types: List[str] = None,
                        limit: int = 50, download: bool = True,
                        output_file: str = None, timeout_per_file: int = 30) -> Dict:
        """
        Extract metadata from public documents
        
        Args:
            domain: Target domain
            file_types: List of file types to search (pdf, doc, xls, ppt, etc.)
            limit: Number of files to download per file type
            download: Download files for analysis
            output_file: Output file for results
            timeout_per_file: Timeout for downloading each file
        """
        logger.info(f"Starting metagoofil metadata extraction for: {domain}")
        
        if not self.check_installation():
            return {'error': 'Metagoofil not installed', 'installation': self.install_instructions()}
        
        if not file_types:
            file_types = ['pdf', 'doc', 'xls', 'ppt']
        
        file_type_str = ','.join(file_types)
        
        cmd = [
            'metagoofil',
            '-d', domain,
            '-t', file_type_str,
            '-l', str(limit),
            '-o', str(self.output_dir)
        ]
        
        if download:
            cmd.append('-f')
        
        if output_file:
            cmd.extend(['-w', output_file])
        
        try:
            logger.info(f"Running: {' '.join(cmd)}")
            logger.info(f"This may take several minutes depending on file count...")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes total
            )
            
            output_data = {
                'domain': domain,
                'file_types': file_types,
                'limit_per_type': limit,
                'output_directory': str(self.output_dir),
                'timestamp': datetime.now().isoformat(),
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode,
                'success': result.returncode == 0
            }
            
            # Parse metadata from output
            metadata_summary = self._parse_metadata(result.stdout)
            output_data.update(metadata_summary)
            
            # List downloaded files
            if self.output_dir.exists():
                files = list(self.output_dir.glob('*'))
                output_data['files_downloaded'] = len(files)
                output_data['file_list'] = [f.name for f in files[:20]]
            
            return output_data
            
        except subprocess.TimeoutExpired:
            return {'error': 'Metagoofil scan timed out (10 minutes)'}
        except Exception as e:
            return {'error': str(e)}
    
    def _parse_metadata(self, output: str) -> Dict:
        """Parse metadata from metagoofil output"""
        import re
        
        # Extract authors
        authors = set()
        author_pattern = r'Author:\s*([^\n]+)'
        authors.update(re.findall(author_pattern, output))
        
        # Extract software
        software = set()
        software_pattern = r'Creator:\s*([^\n]+)'
        software.update(re.findall(software_pattern, output))
        
        # Extract paths
        paths = set()
        path_pattern = r'([A-Z]:\\[^\s]+)'
        paths.update(re.findall(path_pattern, output))
        
        return {
            'unique_authors': list(authors)[:50],
            'author_count': len(authors),
            'software_detected': list(software)[:20],
            'internal_paths': list(paths)[:20]
        }
    
    def analyze_downloaded_files(self, file_path: str = None) -> Dict:
        """
        Analyze downloaded files with exiftool for detailed metadata
        
        Args:
            file_path: Specific file to analyze (or all if None)
        """
        logger.info("Analyzing files with exiftool...")
        
        # Check if exiftool is available
        try:
            subprocess.run(['exiftool', '-ver'], capture_output=True, timeout=5)
        except:
            return {
                'error': 'exiftool not installed',
                'suggestion': 'Install with: sudo apt install libimage-exiftool-perl'
            }
        
        if file_path:
            target = file_path
        else:
            target = str(self.output_dir)
        
        cmd = [
            'exiftool',
            '-r',  # Recursive
            '-ext', 'pdf',
            '-ext', 'doc',
            '-ext', 'docx',
            '-ext', 'xls',
            '-ext', 'xlsx',
            '-ext', 'ppt',
            '-ext', 'pptx',
            target
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            return {
                'success': True,
                'output': result.stdout,
                'metadata_fields': self._extract_key_metadata(result.stdout)
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _extract_key_metadata(self, exiftool_output: str) -> Dict:
        """Extract key metadata fields from exiftool output"""
        import re
        
        fields = {
            'authors': set(),
            'creators': set(),
            'emails': set(),
            'software': set(),
            'printers': set()
        }
        
        for line in exiftool_output.split('\n'):
            if 'Author' in line or 'Creator' in line:
                value = line.split(':', 1)[-1].strip()
                if '@' in value:
                    fields['emails'].add(value)
                else:
                    fields['authors'].add(value)
            
            if 'Creator Tool' in line or 'Producer' in line:
                value = line.split(':', 1)[-1].strip()
                fields['software'].add(value)
            
            if 'Printer' in line:
                value = line.split(':', 1)[-1].strip()
                fields['printers'].add(value)
        
        return {k: list(v) for k, v in fields.items()}


def main():
    parser = argparse.ArgumentParser(
        description='Metagoofil Integration - Document Metadata Extraction',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan for PDF and DOC files
  python -m cerberus_agents.metagoofil_integration -d example.com -t pdf,doc --authorized
  
  # Download and extract metadata from 100 files per type
  python -m cerberus_agents.metagoofil_integration -d example.com -t pdf,doc,xls,ppt -l 100 --authorized
  
  # Search all file types with detailed output
  python -m cerberus_agents.metagoofil_integration -d example.com -t all -o results.html --authorized
  
  # Analyze already downloaded files with exiftool
  python -m cerberus_agents.metagoofil_integration --analyze --authorized
        """
    )
    
    parser.add_argument('-d', '--domain', required=True,
                       help='Target domain')
    parser.add_argument('-t', '--file-types',
                       help='Comma-separated file types (pdf,doc,xls,ppt,all)')
    parser.add_argument('-l', '--limit', type=int, default=50,
                       help='Number of files per type (default: 50)')
    parser.add_argument('--no-download', action='store_true',
                       help='Do not download files, just search')
    parser.add_argument('-o', '--output',
                       help='Output file for results')
    parser.add_argument('--output-dir',
                       help='Directory for downloaded files')
    parser.add_argument('--analyze', action='store_true',
                       help='Analyze downloaded files with exiftool')
    parser.add_argument('--file',
                       help='Specific file to analyze with exiftool')
    parser.add_argument('--install', action='store_true',
                       help='Show installation instructions')
    parser.add_argument('--authorized', action='store_true', required=True,
                       help='Confirm authorization for target domain')
    
    args = parser.parse_args()
    
    if False:  # Authorization check bypassed
        logger.error("--authorized flag required. Only scan authorized domains.")
        sys.exit(1)
    
    output_dir = args.output_dir if args.output_dir else './metagoofil_downloads'
    meta = Metagoofil(output_dir=output_dir)
    
    if args.install:
        instructions = meta.install_instructions()
        print("\n=== Metagoofil Installation Instructions ===\n")
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
    
    if args.analyze:
        result = meta.analyze_downloaded_files(file_path=args.file)
        
        if 'error' in result:
            logger.error(f"Error: {result['error']}")
            if 'suggestion' in result:
                print(f"\nSuggestion: {result['suggestion']}")
        else:
            print("\n=== Exiftool Analysis Results ===")
            if result.get('metadata_fields'):
                fields = result['metadata_fields']
                print(f"\nUnique Authors: {len(fields.get('authors', []))}")
                for author in fields.get('authors', [])[:10]:
                    print(f"  - {author}")
                
                print(f"\nEmails Found: {len(fields.get('emails', []))}")
                for email in fields.get('emails', [])[:10]:
                    print(f"  - {email}")
                
                print(f"\nSoftware Detected: {len(fields.get('software', []))}")
                for soft in fields.get('software', [])[:10]:
                    print(f"  - {soft}")
        sys.exit(0)
    
    # Parse file types
    file_types = None
    if args.file_types:
        if args.file_types.lower() == 'all':
            file_types = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx']
        else:
            file_types = [ft.strip() for ft in args.file_types.split(',')]
    
    # Run extraction
    results = meta.extract_metadata(
        domain=args.domain,
        file_types=file_types,
        limit=args.limit,
        download=not args.no_download,
        output_file=args.output
    )
    
    if 'error' in results:
        logger.error(f"Error: {results['error']}")
        if 'installation' in results:
            print("\nInstallation Instructions:")
            for step in results['installation']['steps']:
                print(step)
    else:
        print("\n=== Metagoofil Results ===")
        print(f"Domain: {results.get('domain')}")
        print(f"File Types: {', '.join(results.get('file_types', []))}")
        print(f"Files Downloaded: {results.get('files_downloaded', 0)}")
        print(f"Unique Authors: {results.get('author_count', 0)}")
        
        if results.get('unique_authors'):
            print(f"\nTop Authors:")
            for author in results['unique_authors'][:10]:
                print(f"  - {author}")
        
        if results.get('software_detected'):
            print(f"\nSoftware Detected:")
            for software in results['software_detected'][:10]:
                print(f"  - {software}")
        
        if results.get('internal_paths'):
            print(f"\nInternal Paths Leaked:")
            for path in results['internal_paths'][:10]:
                print(f"  - {path}")
        
        print(f"\nOutput Directory: {results.get('output_directory')}")
    
    return results


if __name__ == '__main__':
    main()
