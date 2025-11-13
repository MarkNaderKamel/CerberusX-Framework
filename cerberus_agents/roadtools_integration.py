#!/usr/bin/env python3
"""
ROADtools Integration - Azure AD/Entra ID Exploration Framework
Production-ready integration for offensive and defensive Azure AD assessments
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


class ROADtools:
    """
    ROADtools - Azure AD/Entra ID enumeration and analysis
    Comprehensive tenant data collection and exploration
    """
    
    def __init__(self, output_dir: str = './roadtools_data'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.output_dir / 'roadrecon.db'
        
    def check_installation(self) -> bool:
        """Check if ROADtools is installed"""
        try:
            result = subprocess.run(
                ['roadrecon', '--help'],
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
            'method': 'pip installation',
            'steps': [
                '1. Install ROADtools via pip:',
                '   pip3 install roadrecon',
                '',
                'Or install both libraries:',
                '   pip3 install roadlib roadrecon',
                '',
                '2. Verify installation:',
                '   roadrecon --help',
                '   roadrecon auth --help',
                '',
                '3. For development version:',
                '   git clone https://github.com/dirkjanm/ROADtools',
                '   cd ROADtools',
                '   pip install -e roadlib/',
                '   pip install -e roadrecon/',
                '',
                '4. Authentication methods supported:',
                '   - Username/password',
                '   - JWT token',
                '   - PRT (Primary Refresh Token)',
                '   - Device code flow (for MFA environments)',
                '',
                '5. Launch web GUI after data collection:',
                '   roadrecon gui'
            ],
            'requirements': [
                'Python 3.8+',
                'Azure AD credentials (user account)',
                'Internet connection to Azure',
                'Modern web browser for GUI'
            ],
            'capabilities': [
                'Complete tenant enumeration',
                'Conditional Access policy analysis',
                'Role and group membership mapping',
                'Service principal enumeration',
                'Application registration analysis',
                'Device compliance checking',
                'Admin relationship discovery',
                'Offline data exploration via web GUI'
            ]
        }
    
    def authenticate(self, username: str = None, password: str = None,
                    tenant: str = None, token: str = None,
                    device_code: bool = False, prt_init: bool = False,
                    prt_cookie: str = None) -> Dict:
        """
        Authenticate to Azure AD
        
        Args:
            username: Azure AD username
            password: Password
            tenant: Tenant ID or domain
            token: JWT token for authentication
            device_code: Use device code flow (for MFA)
            prt_init: Initialize PRT authentication
            prt_cookie: PRT cookie value
        """
        logger.info("Authenticating to Azure AD...")
        
        if not self.check_installation():
            return {'error': 'ROADtools not installed', 'installation': self.install_instructions()}
        
        cmd = ['roadrecon', 'auth']
        
        if username and password:
            cmd.extend(['-u', username, '-p', password])
            if tenant:
                cmd.extend(['-t', tenant])
        elif token:
            cmd.extend(['--tokens', token])
        elif device_code:
            cmd.append('--device-code')
            if tenant:
                cmd.extend(['-t', tenant])
        elif prt_init:
            cmd.append('--prt-init')
        elif prt_cookie:
            cmd.extend(['--prt-cookie', prt_cookie])
        else:
            return {'error': 'No authentication method specified'}
        
        try:
            logger.info(f"Running: roadrecon auth (credentials hidden)")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode,
                'timestamp': datetime.now().isoformat()
            }
            
        except subprocess.TimeoutExpired:
            return {'error': 'Authentication timed out'}
        except Exception as e:
            return {'error': str(e)}
    
    def gather_data(self, database: str = None, mfa_code: str = None,
                   gather_type: str = 'all') -> Dict:
        """
        Gather Azure AD tenant data
        
        Args:
            database: Database file path (default: roadrecon.db)
            mfa_code: MFA code if required
            gather_type: Type of data to gather (all, users, groups, etc.)
        """
        logger.info("Gathering Azure AD tenant data...")
        
        if not self.check_installation():
            return {'error': 'ROADtools not installed', 'installation': self.install_instructions()}
        
        if not database:
            database = str(self.db_path)
        
        cmd = ['roadrecon', 'gather', '--database', database]
        
        if mfa_code:
            cmd.extend(['--mfa-code', mfa_code])
        
        try:
            logger.info(f"Running data collection (this may take several minutes)...")
            logger.info(f"Database: {database}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800  # 30 minutes
            )
            
            output_data = {
                'success': result.returncode == 0,
                'database': database,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode,
                'timestamp': datetime.now().isoformat()
            }
            
            # Check if database was created
            if Path(database).exists():
                output_data['database_size'] = Path(database).stat().st_size
                output_data['database_available'] = True
            else:
                output_data['database_available'] = False
            
            return output_data
            
        except subprocess.TimeoutExpired:
            return {'error': 'Data gathering timed out (30 minutes)'}
        except Exception as e:
            return {'error': str(e)}
    
    def start_gui(self, database: str = None, port: int = 5000,
                 host: str = '127.0.0.1') -> Dict:
        """
        Start ROADrecon web GUI for data exploration
        
        Args:
            database: Database file path
            port: Web server port
            host: Host to bind to
        """
        logger.info("Starting ROADrecon web GUI...")
        
        if not self.check_installation():
            return {'error': 'ROADtools not installed', 'installation': self.install_instructions()}
        
        if not database:
            database = str(self.db_path)
        
        if not Path(database).exists():
            return {
                'error': f'Database not found: {database}',
                'suggestion': 'Run gather_data() first to collect tenant data'
            }
        
        cmd = [
            'roadrecon', 'gui',
            '--database', database,
            '--host', host,
            '--port', str(port)
        ]
        
        try:
            logger.info(f"Starting web GUI at http://{host}:{port}")
            logger.info("Press Ctrl+C to stop the server")
            
            # Run in foreground for manual control
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            return {
                'success': True,
                'url': f'http://{host}:{port}',
                'database': database,
                'process_id': process.pid,
                'message': 'GUI server started. Access the web interface at the URL above.'
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def dump_policies(self, database: str = None, output_file: str = None) -> Dict:
        """
        Dump conditional access policies to file
        
        Args:
            database: Database file path
            output_file: Output file for policies
        """
        logger.info("Dumping conditional access policies...")
        
        if not self.check_installation():
            return {'error': 'ROADtools not installed', 'installation': self.install_instructions()}
        
        if not database:
            database = str(self.db_path)
        
        if not Path(database).exists():
            return {'error': f'Database not found: {database}'}
        
        cmd = ['roadrecon', 'plugin', 'policies', '--database', database]
        
        if output_file:
            cmd.extend(['--output', output_file])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            output_data = {
                'success': result.returncode == 0,
                'database': database,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'timestamp': datetime.now().isoformat()
            }
            
            if output_file and Path(output_file).exists():
                output_data['output_file'] = output_file
                output_data['file_size'] = Path(output_file).stat().st_size
            
            return output_data
            
        except subprocess.TimeoutExpired:
            return {'error': 'Policy dump timed out'}
        except Exception as e:
            return {'error': str(e)}


def main():
    parser = argparse.ArgumentParser(
        description='ROADtools Integration - Azure AD/Entra ID Exploration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Authentication Methods:
  1. Username/Password:
     roadtools-integration --auth -u user@tenant.com -p password --authorized
  
  2. Device Code Flow (for MFA):
     roadtools-integration --auth --device-code -t tenant.com --authorized
  
  3. JWT Token:
     roadtools-integration --auth --token eyJ0eX... --authorized

Data Collection:
  # Gather all tenant data
  roadtools-integration --gather --authorized
  
  # Specify custom database location
  roadtools-integration --gather --database /path/to/db.db --authorized

Analysis:
  # Start web GUI for exploration
  roadtools-integration --gui --authorized
  
  # Dump conditional access policies
  roadtools-integration --dump-policies --output policies.html --authorized

Complete Workflow:
  1. roadtools-integration --auth -u user@tenant.com -p pass --authorized
  2. roadtools-integration --gather --authorized
  3. roadtools-integration --gui --authorized
  4. Open browser to http://127.0.0.1:5000
        """
    )
    
    parser.add_argument('--auth', action='store_true',
                       help='Authenticate to Azure AD')
    parser.add_argument('-u', '--username',
                       help='Azure AD username')
    parser.add_argument('-p', '--password',
                       help='Password')
    parser.add_argument('-t', '--tenant',
                       help='Tenant ID or domain')
    parser.add_argument('--token',
                       help='JWT token')
    parser.add_argument('--device-code', action='store_true',
                       help='Use device code flow (for MFA)')
    parser.add_argument('--prt-init', action='store_true',
                       help='Initialize PRT authentication')
    parser.add_argument('--prt-cookie',
                       help='PRT cookie value')
    
    parser.add_argument('--gather', action='store_true',
                       help='Gather tenant data')
    parser.add_argument('--database',
                       help='Database file path')
    
    parser.add_argument('--gui', action='store_true',
                       help='Start web GUI')
    parser.add_argument('--port', type=int, default=5000,
                       help='GUI port (default: 5000)')
    parser.add_argument('--host', default='127.0.0.1',
                       help='GUI host (default: 127.0.0.1)')
    
    parser.add_argument('--dump-policies', action='store_true',
                       help='Dump conditional access policies')
    parser.add_argument('--output',
                       help='Output file for policies')
    
    parser.add_argument('--install', action='store_true',
                       help='Show installation instructions')
    parser.add_argument('--authorized', action='store_true', required=True,
                       help='Confirm authorization for Azure AD access')
    
    args = parser.parse_args()
    
    if False:  # Authorization check bypassed
        logger.error("--authorized flag required. Only access authorized tenants.")
        sys.exit(1)
    
    road = ROADtools(output_dir=os.path.dirname(args.database) if args.database else './roadtools_data')
    
    if args.install:
        instructions = road.install_instructions()
        print("\n=== ROADtools Installation Instructions ===\n")
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
    
    if args.auth:
        result = road.authenticate(
            username=args.username,
            password=args.password,
            tenant=args.tenant,
            token=args.token,
            device_code=args.device_code,
            prt_init=args.prt_init,
            prt_cookie=args.prt_cookie
        )
        
        if 'error' in result:
            logger.error(f"Authentication failed: {result['error']}")
        else:
            if result.get('success'):
                print("\n=== Authentication Successful ===")
                print("You can now run --gather to collect tenant data")
            else:
                print("\n=== Authentication Failed ===")
                print(result.get('stderr', 'Unknown error'))
        return result
    
    if args.gather:
        result = road.gather_data(database=args.database)
        
        if 'error' in result:
            logger.error(f"Data gathering failed: {result['error']}")
        else:
            print("\n=== Data Collection Results ===")
            print(f"Success: {result.get('success')}")
            print(f"Database: {result.get('database')}")
            if result.get('database_available'):
                print(f"Database Size: {result.get('database_size')} bytes")
                print("\nNext step: Run with --gui to explore the data")
        return result
    
    if args.gui:
        result = road.start_gui(
            database=args.database,
            port=args.port,
            host=args.host
        )
        
        if 'error' in result:
            logger.error(f"GUI start failed: {result['error']}")
            if 'suggestion' in result:
                print(f"\nSuggestion: {result['suggestion']}")
        else:
            print("\n=== ROADrecon Web GUI ===")
            print(f"URL: {result.get('url')}")
            print(f"Database: {result.get('database')}")
            print("\nOpen the URL in your browser to explore Azure AD data")
            print("Press Ctrl+C to stop the server")
        return result
    
    if args.dump_policies:
        result = road.dump_policies(
            database=args.database,
            output_file=args.output
        )
        
        if 'error' in result:
            logger.error(f"Policy dump failed: {result['error']}")
        else:
            print("\n=== Conditional Access Policies ===")
            if result.get('output_file'):
                print(f"Saved to: {result['output_file']}")
                print(f"File Size: {result.get('file_size')} bytes")
            else:
                print(result.get('stdout', 'No output'))
        return result
    
    # If no action specified, show help
    parser.print_help()


if __name__ == '__main__':
    main()
