#!/usr/bin/env python3
"""
Mythic C2 Framework Integration
Modular C2 with operator-friendly analytics and multiple payload types
Docker-based deployment with advanced tracking capabilities
"""

import subprocess
import json
import requests
import logging
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MythicC2Framework:
    """Production-ready Mythic C2 Framework integration"""
    
    def __init__(self, api_url: str = "https://127.0.0.1:7443", api_key: str = None):
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.headers = {"apitoken": api_key} if api_key else {}
    
    def check_installation(self) -> Dict[str, any]:
        """Check if Mythic is installed (Docker)"""
        result = {
            "installed": False,
            "docker_available": False,
            "mythic_running": False,
            "install_commands": [
                "git clone https://github.com/its-a-feature/Mythic.git",
                "cd Mythic",
                "./install_docker_ubuntu.sh",
                "make"
            ]
        }
        
        try:
            docker_check = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                timeout=5
            )
            result["docker_available"] = docker_check.returncode == 0
            
            if result["docker_available"]:
                container_check = subprocess.run(
                    ["docker", "ps", "--filter", "name=mythic", "--format", "{{.Names}}"],
                    capture_output=True,
                    timeout=5
                )
                result["mythic_running"] = b"mythic" in container_check.stdout.lower()
                result["installed"] = result["mythic_running"]
        except Exception as e:
            logger.warning(f"Docker check failed: {e}")
        
        return result
    
    def start_mythic(self, mythic_dir: str = "./Mythic") -> Dict[str, any]:
        """Start Mythic server via Docker Compose"""
        try:
            cmd = ["make"]
            process = subprocess.Popen(
                cmd,
                cwd=mythic_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            return {
                "success": True,
                "message": "Mythic starting...",
                "pid": process.pid,
                "url": "https://127.0.0.1:7443"
            }
        except Exception as e:
            return {"error": str(e)}
    
    def list_payloads(self) -> List[Dict[str, any]]:
        """List available payload types (Apfell, Apollo, etc.)"""
        if not self.api_key:
            return [{"error": "API key required"}]
        
        try:
            response = requests.get(
                f"{self.api_url}/api/v1.4/payloadtypes",
                headers=self.headers,
                verify=False,
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            return [{"error": f"API returned {response.status_code}"}]
        except Exception as e:
            return [{"error": str(e)}]
    
    def create_payload(self, payload_type: str, c2_profile: str = "http",
                      params: Dict = None) -> Dict[str, any]:
        """
        Create Mythic payload
        
        Args:
            payload_type: Agent type (apollo, apfell, poseidon, etc.)
            c2_profile: C2 channel (http, https, tcp, dns, smb)
            params: Additional parameters
        """
        if not self.api_key:
            return {"error": "API key required"}
        
        payload_data = {
            "payload_type": payload_type,
            "c2_profile": c2_profile,
            "build_parameters": params or {}
        }
        
        try:
            response = requests.post(
                f"{self.api_url}/api/v1.4/payloads",
                headers=self.headers,
                json=payload_data,
                verify=False,
                timeout=30
            )
            return response.json() if response.status_code == 200 else {"error": response.text}
        except Exception as e:
            return {"error": str(e)}
    
    def list_callbacks(self) -> List[Dict[str, any]]:
        """List active agent callbacks"""
        if not self.api_key:
            return [{"error": "API key required"}]
        
        try:
            response = requests.get(
                f"{self.api_url}/api/v1.4/callbacks",
                headers=self.headers,
                verify=False,
                timeout=10
            )
            return response.json() if response.status_code == 200 else []
        except Exception as e:
            logger.error(f"Failed to list callbacks: {e}")
            return []
    
    def task_callback(self, callback_id: str, command: str, params: Dict = None) -> Dict[str, any]:
        """Execute task on callback"""
        if not self.api_key:
            return {"error": "API key required"}
        
        task_data = {
            "command": command,
            "params": params or {}
        }
        
        try:
            response = requests.post(
                f"{self.api_url}/api/v1.4/callbacks/{callback_id}/tasks",
                headers=self.headers,
                json=task_data,
                verify=False,
                timeout=30
            )
            return response.json() if response.status_code == 200 else {"error": response.text}
        except Exception as e:
            return {"error": str(e)}
    
    def get_info(self) -> Dict[str, any]:
        """Get Mythic framework information"""
        return {
            "name": "Mythic C2 Framework",
            "description": "Modular C2 with operator-friendly analytics",
            "features": [
                "Multi-agent support (Apollo, Apfell, Poseidon, Athena)",
                "Multiple C2 protocols (HTTP, HTTPS, TCP, DNS, SMB)",
                "Web UI with real-time tracking",
                "Advanced operator analytics",
                "Docker-based deployment",
                "API-driven automation",
                "Integrated Mimikatz for lateral movement"
            ],
            "agent_types": {
                "Apollo": ".NET agent for Windows",
                "Apfell": "JavaScript agent for macOS",
                "Poseidon": "Python agent for Linux/macOS",
                "Athena": "C# agent with advanced features"
            },
            "c2_profiles": ["http", "https", "tcp", "dns", "smb", "websocket"],
            "deployment": "Docker Compose",
            "default_port": 7443,
            "github": "https://github.com/its-a-feature/Mythic"
        }


def main():
    """CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Mythic C2 Framework Integration")
    parser.add_argument("--check", action="store_true", help="Check installation")
    parser.add_argument("--info", action="store_true", help="Show framework info")
    parser.add_argument("--api-url", default="https://127.0.0.1:7443", help="Mythic API URL")
    parser.add_argument("--api-key", help="Mythic API key")
    parser.add_argument("--payloads", action="store_true", help="List payload types")
    parser.add_argument("--callbacks", action="store_true", help="List active callbacks")
    parser.add_argument('--authorized', action='store_true',
                       help='Confirm you have authorization to perform this action')
    args = parser.parse_args()
    
    mythic = MythicC2Framework(api_url=args.api_url, api_key=args.api_key)
    
    if args.check:
        status = mythic.check_installation()
        print("\n═══ Mythic C2 Installation Status ═══")
        print(f"Docker Available: {status['docker_available']}")
        print(f"Mythic Running: {status['mythic_running']}")
        print(f"Installed: {status['installed']}")
        if not status['installed']:
            print(f"\n📥 Installation Commands:")
            for cmd in status['install_commands']:
                print(f"   {cmd}")
    
    elif args.info:
        info = mythic.get_info()
        print("\n═══ Mythic C2 Framework Info ═══")
        print(f"Name: {info['name']}")
        print(f"Description: {info['description']}")
        print(f"\n🎯 Features:")
        for feature in info['features']:
            print(f"   • {feature}")
        print(f"\n🤖 Agent Types:")
        for agent, desc in info['agent_types'].items():
            print(f"   • {agent}: {desc}")
        print(f"\n📡 C2 Profiles: {', '.join(info['c2_profiles'])}")
        print(f"🔗 GitHub: {info['github']}")
    
    elif args.payloads:
        payloads = mythic.list_payloads()
        print(f"\n📦 Available Payload Types:")
        for payload in payloads:
            if "error" not in payload:
                print(f"   • {payload.get('name', 'Unknown')}")
    
    elif args.callbacks:
        callbacks = mythic.list_callbacks()
        print(f"\n📡 Active Callbacks: {len(callbacks)}")
        for callback in callbacks:
            if "error" not in callback:
                print(f"   ID: {callback.get('id')}")
                print(f"   Host: {callback.get('host')}")
                print(f"   User: {callback.get('user')}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
