#!/usr/bin/env python3
"""
Havoc C2 Framework Integration
Modern Command & Control framework - Cobalt Strike alternative
Production-ready post-exploitation and lateral movement
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


class HavocC2:
    """
    Havoc C2 Framework integration
    Modern alternative to Cobalt Strike for red team operations
    """
    
    def __init__(self, havoc_dir: Optional[str] = None):
        self.havoc_dir = havoc_dir or str(Path.home() / "Havoc")
        
    def check_installation(self) -> bool:
        """Check if Havoc is installed"""
        havoc_server = Path(self.havoc_dir) / "havoc-server"
        havoc_client = Path(self.havoc_dir) / "havoc-client"
        
        if havoc_server.exists() and havoc_client.exists():
            logger.info(f"Havoc C2 found at: {self.havoc_dir}")
            return True
        
        logger.error("Havoc C2 not installed")
        return False
    
    def install_havoc(self) -> Dict:
        """
        Installation instructions for Havoc C2
        """
        return {
            'installation': 'manual',
            'requirements': [
                'Ubuntu 22.04 or Debian 12 (recommended)',
                'Go 1.19+',
                'Python 3.10+',
                'Qt5 (for client GUI)',
                'Docker (optional, for containerized deployment)'
            ],
            'steps': [
                '1. Install dependencies:',
                '   sudo apt update',
                '   sudo apt install -y git build-essential cmake python3-dev qtbase5-dev',
                '',
                '2. Clone Havoc repository:',
                f'   git clone https://github.com/HavocFramework/Havoc.git {self.havoc_dir}',
                f'   cd {self.havoc_dir}',
                '',
                '3. Build the teamserver:',
                '   cd teamserver',
                '   go mod download',
                '   make',
                '',
                '4. Build the client:',
                '   cd ../client',
                '   make',
                '',
                '5. Create teamserver profile:',
                '   Edit profiles/havoc.yaotl for your infrastructure',
                '',
                '6. Start teamserver:',
                '   ./teamserver server --profile ./profiles/havoc.yaotl',
                '',
                '7. Connect client:',
                '   ./havoc-client'
            ],
            'docker_alternative': [
                'Or use Docker:',
                f'cd {self.havoc_dir}',
                'docker compose up -d'
            ]
        }
    
    def generate_teamserver_profile(self, output_file: str, 
                                   server_host: str = '0.0.0.0',
                                   server_port: int = 40056,
                                   password: str = 'changeme') -> Dict:
        """
        Generate Havoc teamserver profile
        """
        profile = f"""Teamserver {{
    Host = "{server_host}"
    Port = {server_port}

    Build {{
        Compiler64 = "data/x86_64-w64-mingw32-cross/bin/x86_64-w64-mingw32-gcc"
        Compiler86 = "data/i686-w64-mingw32-cross/bin/i686-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
    }}
}}

Operators {{
    user "admin" {{
        Password = "{password}"
    }}
}}

Listeners {{
    Http {{
        Name         = "HTTP Listener"
        Hosts        = ["0.0.0.0"]
        HostBind     = "0.0.0.0"
        HostRotation = "round-robin"
        Port         = 443
        PortBind     = 443
        PortConn     = 443

        Secure      = true
        KillDate    = "2026-01-01"
        WorkingHours = "00:00-23:59"

        Headers = [
            "X-Havoc: true",
        ]

        Uris = [
            "/login",
            "/api/v1",
        ]

        UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

        HostHeader = ""
    }}
}}

Demon {{
    Sleep = 2
    Jitter = 20

    TrustXForwardedFor = false

    Injection {{
        Spawn64 = "C:\\\\Windows\\\\System32\\\\notepad.exe"
        Spawn32 = "C:\\\\Windows\\\\SysWOW64\\\\notepad.exe"
    }}
}}
"""
        
        try:
            with open(output_file, 'w') as f:
                f.write(profile)
            
            logger.info(f"Teamserver profile created: {output_file}")
            logger.warning(f"⚠️  Change the password in {output_file}!")
            
            return {
                'status': 'created',
                'file': output_file,
                'host': server_host,
                'port': server_port
            }
            
        except Exception as e:
            logger.error(f"Error creating profile: {e}")
            return {'error': str(e)}
    
    def generate_listener_config(self, listener_type: str = 'http',
                                port: int = 443, domain: str = '') -> Dict:
        """
        Generate listener configuration
        
        Types: http, https, smb, external
        """
        configs = {
            'http': {
                'type': 'HTTP',
                'port': port,
                'hosts': ['0.0.0.0'],
                'uris': ['/login', '/api', '/images'],
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'headers': {
                    'X-Forwarded-For': '{{ip}}',
                    'Server': 'nginx/1.18.0'
                }
            },
            'https': {
                'type': 'HTTPS',
                'port': port,
                'hosts': [domain] if domain else ['0.0.0.0'],
                'secure': True,
                'cert_path': '/path/to/cert.pem',
                'key_path': '/path/to/key.pem'
            },
            'smb': {
                'type': 'SMB',
                'pipe_name': 'mojo.5688.8052.35656683834927365',
                'kill_date': '2026-01-01'
            }
        }
        
        return configs.get(listener_type, {})
    
    def generate_payload_template(self, payload_type: str = 'exe',
                                 arch: str = 'x64') -> str:
        """
        Generate demon agent payload
        
        Types: exe, dll, shellcode, service_exe
        Architectures: x64, x86
        """
        instructions = f"""
# Generate Havoc Demon Agent

## From Havoc Client GUI:
1. Attack → Payload
2. Select listener
3. Format: {payload_type}
4. Architecture: {arch}
5. Indirect Syscalls: Enabled
6. Sleep obfuscation: Enabled
7. Generate

## From Teamserver (API):
curl -X POST https://teamserver:40056/api/demon/generate \\
  -H "Authorization: Bearer {{TOKEN}}" \\
  -d '{{
    "listener": "HTTP Listener",
    "arch": "{arch}",
    "format": "{payload_type}",
    "config": {{
      "sleep": 3,
      "jitter": 20,
      "indirect_syscalls": true,
      "sleep_obfuscation": true
    }}
  }}'

## Available Formats:
- Windows Executable (.exe)
- Windows DLL (.dll)
- Windows Service (.exe)
- Shellcode (.bin)
- PowerShell (.ps1)
"""
        
        return instructions
    
    def list_post_exploitation_modules(self) -> List[str]:
        """List Havoc post-exploitation capabilities"""
        modules = [
            "Process Management",
            "  - ps              : List processes",
            "  - kill            : Terminate process",
            "  - inject          : Inject shellcode/DLL",
            "",
            "Credential Access",
            "  - token           : Token manipulation (steal, make, impersonate)",
            "  - mimikatz        : Run Mimikatz commands",
            "  - pth             : Pass-the-Hash",
            "",
            "Lateral Movement",
            "  - jump            : WMI, PSExec, SSH lateral movement",
            "  - pivot           : SOCKS4/5 proxy",
            "  - rportfwd        : Reverse port forwarding",
            "",
            "Execution",
            "  - execute-assembly : Execute .NET assembly",
            "  - inline-execute   : BOF (Beacon Object File)",
            "  - powershell       : PowerShell execution",
            "  - shell            : CMD shell",
            "",
            "File Operations",
            "  - upload/download : File transfer",
            "  - ls/cd/pwd       : Directory navigation",
            "",
            "Network",
            "  - netstat         : Network connections",
            "  - portscan        : Port scanner",
            "  - screenshot      : Capture screenshot",
            "",
            "Persistence",
            "  - persist         : Registry, scheduled task, service"
        ]
        
        return modules
    
    def generate_opsec_guide(self) -> str:
        """Generate operational security guidelines for Havoc"""
        guide = """
═══════════════════════════════════════════════════════════════
HAVOC C2 OPSEC GUIDE
═══════════════════════════════════════════════════════════════

1. INFRASTRUCTURE SETUP
   ✓ Use redirectors (Apache/Nginx) in front of teamserver
   ✓ Implement domain fronting for HTTPS traffic
   ✓ Use legitimate-looking domain names
   ✓ Rotate infrastructure regularly
   ✓ Separate C2 and payload hosting servers

2. PAYLOAD CONFIGURATION
   ✓ Enable sleep obfuscation
   ✓ Use indirect syscalls
   ✓ Randomize sleep/jitter values
   ✓ Set reasonable kill dates
   ✓ Obfuscate strings and imports
   ✓ Sign executables with valid certificates

3. EVASION TECHNIQUES
   ✓ Module stomping for DLL injection
   ✓ AMSI/ETW patching
   ✓ Unhooking NTDLL
   ✓ Stack spoofing
   ✓ Custom malleable C2 profiles

4. OPERATIONAL BEST PRACTICES
   ✓ Limit active hours (working hours simulation)
   ✓ Use legitimate user agents
   ✓ Mimic normal network traffic patterns
   ✓ Implement C2 traffic encryption
   ✓ Clean up artifacts after operations

5. DETECTION AVOIDANCE
   ✓ Avoid well-known IOCs
   ✓ Use process hollowing vs injection
   ✓ Clear event logs selectively
   ✓ Disable Windows Defender Real-Time Protection
   ✓ Leverage living-off-the-land binaries (LOLBins)

6. ATTRIBUTION PREVENTION
   ✓ Use VPNs/proxies for teamserver access
   ✓ Separate payload dev from C2 infrastructure
   ✓ Clean metadata from documents
   ✓ Use burner domains/cloud accounts
   ✓ Never reuse infrastructure across campaigns

═══════════════════════════════════════════════════════════════
        """
        
        return guide


def main():
    parser = argparse.ArgumentParser(description="Havoc C2 Framework Integration")
    parser.add_argument('--install', action='store_true', help='Show installation instructions')
    parser.add_argument('--generate-profile', help='Generate teamserver profile')
    parser.add_argument('--server-host', default='0.0.0.0', help='Teamserver host')
    parser.add_argument('--server-port', type=int, default=40056, help='Teamserver port')
    parser.add_argument('--password', default='changeme', help='Operator password')
    parser.add_argument('--listener-config', choices=['http', 'https', 'smb'],
                       help='Generate listener configuration')
    parser.add_argument('--payload-template', choices=['exe', 'dll', 'shellcode'],
                       help='Show payload generation template')
    parser.add_argument('--list-modules', action='store_true',
                       help='List post-exploitation modules')
    parser.add_argument('--opsec-guide', action='store_true',
                       help='Display OPSEC guidelines')
    
    args = parser.parse_args()
    
    havoc = HavocC2()
    
    if args.install:
        instructions = havoc.install_havoc()
        
        print("\n🛠️  Havoc C2 Installation\n")
        print("Requirements:")
        for req in instructions['requirements']:
            print(f"  - {req}")
        
        print("\nInstallation Steps:")
        for step in instructions['steps']:
            print(step)
        
        print("\nDocker Alternative:")
        for step in instructions['docker_alternative']:
            print(step)
        
        return
    
    if args.generate_profile:
        result = havoc.generate_teamserver_profile(
            args.generate_profile,
            args.server_host,
            args.server_port,
            args.password
        )
        
        print(json.dumps(result, indent=2))
        return
    
    if args.listener_config:
        config = havoc.generate_listener_config(args.listener_config)
        print(json.dumps(config, indent=2))
        return
    
    if args.payload_template:
        template = havoc.generate_payload_template(args.payload_template)
        print(template)
        return
    
    if args.list_modules:
        modules = havoc.list_post_exploitation_modules()
        print("\n🔧 Havoc Post-Exploitation Modules:\n")
        for module in modules:
            print(module)
        return
    
    if args.opsec_guide:
        guide = havoc.generate_opsec_guide()
        print(guide)
        return
    
    print("\n⚔️  Havoc C2 Framework - Modern Red Team Platform")
    print("\n✨ Features:")
    print("  - Modern Cobalt Strike alternative")
    print("  - Advanced evasion (indirect syscalls, sleep obfuscation)")
    print("  - Post-exploitation framework")
    print("  - SOCKS4/5 pivoting")
    print("  - Cross-platform (Windows, Linux, macOS)")
    print("  - Open-source and free")
    print("\n⚠️  Authorization Required")
    print("  Only use in authorized red team operations")
    print("\n📚 Resources:")
    print("  https://github.com/HavocFramework/Havoc")
    print("  https://havocframework.com/docs")


if __name__ == "__main__":
    main()
