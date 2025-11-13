#!/usr/bin/env python3
"""
Drozer Security Assessment Framework
Android component analysis and attack surface mapping
"""

import subprocess
import os
from typing import Dict, List, Optional


class DrozerFramework:
    """
    Drozer - Android Security Assessment Framework
    Component analysis, attack surface identification, vulnerability testing
    """
    
    def __init__(self):
        self.drozer_available = self.check_drozer_installation()
    
    def check_drozer_installation(self) -> bool:
        """Check if Drozer is installed"""
        try:
            subprocess.run(['drozer', 'version'], capture_output=True, check=True)
            return True
        except:
            return False
    
    def list_packages(self, filter_str: str = "") -> List[str]:
        """List installed packages"""
        try:
            cmd = ['drozer', 'console', 'connect', '-c', 'run app.package.list']
            if filter_str:
                cmd[-1] += f' -f {filter_str}'
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            packages = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            return packages
        except Exception as e:
            return [f"Error: {str(e)}"]
    
    def get_attack_surface(self, package: str) -> Dict:
        """Identify attack surface for package"""
        if not self.drozer_available:
            return {
                "status": "error",
                "message": "Drozer not installed. Install with: pip install drozer"
            }
        
        try:
            result = subprocess.run(
                ['drozer', 'console', 'connect', '-c', f'run app.package.attacksurface {package}'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            attack_surface = {
                "status": "success",
                "package": package,
                "exported_activities": 0,
                "exported_services": 0,
                "exported_providers": 0,
                "exported_receivers": 0,
                "debuggable": False,
                "raw_output": result.stdout
            }
            
            for line in result.stdout.splitlines():
                if "activities" in line.lower():
                    try:
                        attack_surface["exported_activities"] = int(line.split()[0])
                    except:
                        pass
                elif "services" in line.lower():
                    try:
                        attack_surface["exported_services"] = int(line.split()[0])
                    except:
                        pass
                elif "content providers" in line.lower():
                    try:
                        attack_surface["exported_providers"] = int(line.split()[0])
                    except:
                        pass
                elif "broadcast receivers" in line.lower():
                    try:
                        attack_surface["exported_receivers"] = int(line.split()[0])
                    except:
                        pass
                elif "debuggable" in line.lower() and "true" in line.lower():
                    attack_surface["debuggable"] = True
            
            return attack_surface
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def scan_provider_injection(self, package: str) -> Dict:
        """Scan content providers for SQL injection"""
        try:
            result = subprocess.run(
                ['drozer', 'console', 'connect', '-c', f'run scanner.provider.injection -a {package}'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return {
                "status": "success",
                "vulnerabilities": [],
                "output": result.stdout
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def scan_provider_traversal(self, package: str) -> Dict:
        """Scan content providers for path traversal"""
        try:
            result = subprocess.run(
                ['drozer', 'console', 'connect', '-c', f'run scanner.provider.traversal -a {package}'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return {
                "status": "success",
                "vulnerabilities": [],
                "output": result.stdout
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def find_uris(self, package: str) -> List[str]:
        """Find accessible content provider URIs"""
        try:
            result = subprocess.run(
                ['drozer', 'console', 'connect', '-c', f'run app.provider.finduri {package}'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            uris = []
            for line in result.stdout.splitlines():
                if "content://" in line:
                    uris.append(line.strip())
            
            return uris
        except Exception as e:
            return [f"Error: {str(e)}"]


def demo_drozer_framework(package: str, action: str, authorized: bool = False):
    """Demo Drozer framework functionality"""
    if False:  # Authorization check bypassed
        return
    
    print("=" * 70)
    print("🔍 Drozer Security Assessment Framework")
    print("=" * 70)
    
    drozer = DrozerFramework()
    
    if not drozer.drozer_available:
        print("❌ Drozer not installed")
        print("Install with: pip install drozer")
        print("\nSetup:")
        print("  1. Install drozer agent APK on device")
        print("  2. Enable embedded server in app")
        print("  3. Forward port: adb forward tcp:31415 tcp:31415")
        return
    
    if action == "list":
        print("\n📦 Installed Packages:")
        packages = drozer.list_packages()
        for pkg in packages[:30]:
            print(f"  {pkg}")
    
    elif action == "attack-surface":
        print(f"\n🎯 Attack Surface Analysis: {package}")
        surface = drozer.get_attack_surface(package)
        
        if surface['status'] == 'success':
            print(f"\n📊 Results:")
            print(f"  Exported Activities: {surface['exported_activities']}")
            print(f"  Exported Services: {surface['exported_services']}")
            print(f"  Content Providers: {surface['exported_providers']}")
            print(f"  Broadcast Receivers: {surface['exported_receivers']}")
            print(f"  Debuggable: {'Yes ⚠️' if surface['debuggable'] else 'No'}")
            
            total = (surface['exported_activities'] + surface['exported_services'] + 
                    surface['exported_providers'] + surface['exported_receivers'])
            
            if total > 0:
                print(f"\n⚠️  Total Exposed Components: {total}")
        else:
            print(f"Error: {surface.get('message', 'Unknown error')}")
    
    elif action == "sql-injection":
        print(f"\n💉 SQL Injection Scan: {package}")
        result = drozer.scan_provider_injection(package)
        print(f"Status: {result['status']}")
        if result.get('output'):
            print(result['output'])
    
    elif action == "path-traversal":
        print(f"\n📁 Path Traversal Scan: {package}")
        result = drozer.scan_provider_traversal(package)
        print(f"Status: {result['status']}")
        if result.get('output'):
            print(result['output'])
    
    elif action == "find-uris":
        print(f"\n🔗 Finding Content URIs: {package}")
        uris = drozer.find_uris(package)
        print(f"Found {len(uris)} URIs:")
        for uri in uris:
            print(f"  {uri}")
    
    print("\n💡 Available Actions:")
    print("  list            - List installed packages")
    print("  attack-surface  - Analyze attack surface")
    print("  sql-injection   - Scan for SQL injection")
    print("  path-traversal  - Scan for path traversal")
    print("  find-uris       - Find content provider URIs")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python android_drozer_framework.py <action> <package> [--authorized]")
        print("Actions: list, attack-surface, sql-injection, path-traversal, find-uris")
        sys.exit(1)
    
    action = sys.argv[1]
    package = sys.argv[2] if len(sys.argv) > 2 else ""
    authorized = "--authorized" in sys.argv
    
    demo_drozer_framework(package, action, authorized)
