#!/usr/bin/env python3
"""
GhostPack Suite Integration
Collection of battle-tested C# offensive tools for Windows/AD
Rubeus, Seatbelt, Certify, SharpDPAPI, SharpUp, etc.
"""

import subprocess
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GhostPackSuite:
    """GhostPack offensive toolset for Windows/AD"""
    
    def __init__(self):
        self.tools_dir = str(Path.home() / "GhostPack")
    
    def check_tool_installation(self, tool_name: str) -> Dict[str, any]:
        """Check if a specific GhostPack tool is installed"""
        exe_paths = [
            Path(self.tools_dir) / f"{tool_name}.exe",
            Path.home() / tool_name / "bin" / "Release" / f"{tool_name}.exe",
            Path(f"/opt/GhostPack/{tool_name}.exe"),
        ]
        
        for path in exe_paths:
            if path.exists():
                return {
                    "installed": True,
                    "path": str(path),
                    "tool": tool_name
                }
        
        return {
            "installed": False,
            "tool": tool_name,
            "download_url": f"https://github.com/GhostPack/{tool_name}/releases",
            "compile_instructions": [
                f"git clone https://github.com/GhostPack/{tool_name}.git",
                f"cd {tool_name}",
                "# Open .sln in Visual Studio or use:",
                "msbuild /p:Configuration=Release",
                f"# Binary will be in bin/Release/{tool_name}.exe"
            ]
        }
    
    def execute_tool(self, tool_name: str, args: str = "") -> Dict[str, any]:
        """Execute a GhostPack tool with arguments"""
        check = self.check_tool_installation(tool_name)
        
        if not check["installed"]:
            return {
                "error": f"{tool_name} not installed",
                "instructions": check["compile_instructions"]
            }
        
        try:
            cmd = [check["path"]] + args.split() if args else [check["path"]]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return {
                "success": True,
                "tool": tool_name,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
        except subprocess.TimeoutExpired:
            return {"error": "Execution timed out"}
        except Exception as e:
            return {"error": str(e)}
    
    def get_tools(self) -> Dict[str, Dict[str, any]]:
        """Get GhostPack tools information"""
        return {
            "Rubeus": {
                "description": "Kerberos abuse toolkit",
                "features": [
                    "Kerberoasting",
                    "AS-REP roasting",
                    "Pass-the-ticket",
                    "Golden/Silver ticket creation",
                    "Ticket renewal",
                    "S4U abuse"
                ],
                "github": "https://github.com/GhostPack/Rubeus"
            },
            "Seatbelt": {
                "description": "Host enumeration for situational awareness",
                "features": [
                    "System information collection",
                    "Security product detection",
                    "Network configuration",
                    "Interesting files/registry",
                    "User/group enumeration",
                    "Scheduled tasks"
                ],
                "github": "https://github.com/GhostPack/Seatbelt"
            },
            "Certify": {
                "description": "AD Certificate Services attack tool",
                "features": [
                    "Vulnerable template enumeration",
                    "ESC1-ESC8 attacks",
                    "Certificate request abuse",
                    "CA configuration enumeration"
                ],
                "github": "https://github.com/GhostPack/Certify"
            },
            "SharpDPAPI": {
                "description": "DPAPI credential extraction",
                "features": [
                    "Chrome credential extraction",
                    "RDP credential extraction",
                    "Vault credential extraction",
                    "Master key decryption"
                ],
                "github": "https://github.com/GhostPack/SharpDPAPI"
            },
            "SharpUp": {
                "description": "Privilege escalation checks",
                "features": [
                    "Service binary hijacking",
                    "DLL hijacking",
                    "Registry autoruns",
                    "Scheduled task abuse",
                    "AlwaysInstallElevated"
                ],
                "github": "https://github.com/GhostPack/SharpUp"
            },
            "SharpRoast": {
                "description": "Kerberoasting in C#",
                "features": [
                    "SPN enumeration",
                    "TGS request",
                    "Hashcat format output"
                ],
                "github": "https://github.com/GhostPack/SharpRoast"
            },
            "SafetyKatz": {
                "description": "Mimikatz .NET wrapper",
                "features": [
                    "Credential dumping",
                    "In-memory execution",
                    "Process injection"
                ],
                "github": "https://github.com/GhostPack/SafetyKatz"
            }
        }
    
    def get_info(self) -> Dict[str, any]:
        """Get GhostPack suite information"""
        return {
            "name": "GhostPack Suite",
            "description": "Collection of C# offensive security tools",
            "maintainer": "SpecterOps (formerly Harmj0y/Rueus)",
            "features": [
                "All tools written in C#",
                "In-memory execution capable",
                "No external dependencies",
                "Reflective loading support",
                "Active Directory focused",
                "Windows privilege escalation"
            ],
            "tools": list(self.get_tools().keys()),
            "use_cases": [
                "Kerberos attacks (Rubeus)",
                "Host enumeration (Seatbelt)",
                "AD CS exploitation (Certify)",
                "Credential extraction (SharpDPAPI)",
                "Privilege escalation (SharpUp)"
            ],
            "execution_methods": [
                "Standalone EXE compilation",
                "C2 framework execute-assembly",
                "Reflective DLL injection",
                "PowerShell inline loading"
            ]
        }


def main():
    """CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description="GhostPack Suite")
    parser.add_argument("--info", action="store_true", help="Show suite info")
    parser.add_argument("--list-tools", action="store_true", help="List all tools")
    parser.add_argument("--tool", help="Tool name")
    parser.add_argument("--check", action="store_true", help="Check tool installation")
    parser.add_argument("--execute", help="Execute tool with arguments")
    
        parser.add_argument('--authorized', action='store_true',
                       help='Confirm you have authorization to perform this action')
    args = parser.parse_args()
    
    ghostpack = GhostPackSuite()
    
    if args.info:
        info = ghostpack.get_info()
        print(f"\n═══ {info['name']} ═══")
        print(f"Maintainer: {info['maintainer']}")
        print(f"Description: {info['description']}")
        print(f"\n🎯 Features:")
        for feature in info['features']:
            print(f"   • {feature}")
        print(f"\n🛠️ Tools: {', '.join(info['tools'])}")
    
    elif args.list_tools:
        tools = ghostpack.get_tools()
        print(f"\n═══ GhostPack Tools ═══")
        for tool_name, tool_info in tools.items():
            print(f"\n{tool_name}:")
            print(f"  {tool_info['description']}")
            print(f"  GitHub: {tool_info['github']}")
    
    elif args.check and args.tool:
        result = ghostpack.check_tool_installation(args.tool)
        print(f"\n═══ {args.tool} Installation Status ═══")
        print(f"Installed: {result['installed']}")
        if result['installed']:
            print(f"Path: {result['path']}")
        else:
            print(f"\n📥 Compile Instructions:")
            for instruction in result.get('compile_instructions', []):
                print(f"   {instruction}")
            print(f"\n🔗 Download: {result.get('download_url', '')}")
    
    elif args.execute and args.tool:
        print(f"\n⚡ Executing {args.tool} {args.execute}...")
        result = ghostpack.execute_tool(args.tool, args.execute)
        if "success" in result:
            print(f"\n✅ Execution completed (exit code: {result['returncode']})")
            print(f"\nOutput:\n{result['stdout']}")
            if result['stderr']:
                print(f"\nErrors:\n{result['stderr']}")
        else:
            print(f"\n❌ Error: {result.get('error')}")
            if "instructions" in result:
                print(f"\nInstallation required:")
                for instruction in result['instructions']:
                    print(f"   {instruction}")
    
    elif args.tool:
        tools = ghostpack.get_tools()
        if args.tool in tools:
            tool = tools[args.tool]
            print(f"\n═══ {args.tool} ═══")
            print(f"Description: {tool['description']}")
            print(f"\nFeatures:")
            for feature in tool['features']:
                print(f"   • {feature}")
            print(f"\nGitHub: {tool['github']}")
            
            check = ghostpack.check_tool_installation(args.tool)
            print(f"\nInstalled: {check['installed']}")
            if check['installed']:
                print(f"Path: {check['path']}")
        else:
            print(f"Tool '{args.tool}' not found")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
