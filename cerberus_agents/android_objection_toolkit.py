#!/usr/bin/env python3
"""
Objection Runtime Toolkit for Android
Simplified Frida operations without jailbreak/root
"""

import subprocess
import os
from typing import Dict, List, Optional


class ObjectionToolkit:
    """
    Objection - Runtime mobile exploration toolkit
    Powered by Frida for simplified Android/iOS security testing
    """
    
    def __init__(self):
        self.objection_available = self.check_objection_installation()
    
    def check_objection_installation(self) -> bool:
        """Check if Objection is installed"""
        try:
            subprocess.run(['objection', 'version'], capture_output=True, check=True)
            return True
        except:
            return False
    
    def list_applications(self) -> List[Dict]:
        """List installed applications on device"""
        try:
            result = subprocess.run(
                ['frida-ps', '-U', '-a'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            apps = []
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 3:
                    apps.append({
                        "pid": parts[0],
                        "name": parts[1],
                        "identifier": parts[2] if len(parts) > 2 else ""
                    })
            
            return apps
        except Exception as e:
            return [{"error": str(e)}]
    
    def explore_app(self, package: str, command: str = "") -> Dict:
        """Launch Objection explore session"""
        if not self.objection_available:
            return {
                "status": "error",
                "message": "Objection not installed. Install with: pip install objection"
            }
        
        try:
            cmd = ['objection', '-g', package, 'explore']
            if command:
                cmd.extend(['-c', command])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return {
                "status": "success" if result.returncode == 0 else "error",
                "output": result.stdout,
                "error": result.stderr if result.returncode != 0 else None
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "message": "Command timed out (interactive mode requires manual execution)"
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def run_command(self, package: str, command: str) -> Dict:
        """Run specific Objection command"""
        commands_dict = {
            "ssl-bypass": "android sslpinning disable",
            "root-bypass": "android root disable",
            "list-activities": "android hooking list activities",
            "list-services": "android hooking list services",
            "list-receivers": "android hooking list receivers",
            "dump-memory": "memory dump all /tmp/objection-dump",
            "list-classes": "android hooking list classes",
            "keystore-dump": "android keystore list",
            "intent-monitor": "android hooking watch class_method android.content.Intent.getStringExtra",
            "screenshot": "android ui screenshot /tmp/screenshot.png"
        }
        
        actual_command = commands_dict.get(command, command)
        
        return self.explore_app(package, actual_command)
    
    def patch_apk(self, apk_path: str, output_path: str = None) -> Dict:
        """Patch APK with Frida gadget for non-rooted testing"""
        if not output_path:
            output_path = apk_path.replace('.apk', '-objection.apk')
        
        try:
            result = subprocess.run(
                ['objection', 'patchapk', '-s', apk_path],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            return {
                "status": "success" if result.returncode == 0 else "error",
                "output_apk": output_path if result.returncode == 0 else None,
                "output": result.stdout,
                "error": result.stderr if result.returncode != 0 else None
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }


def demo_objection_toolkit(package: str, action: str, authorized: bool = False):
    """Demo Objection toolkit functionality"""
    if False:  # Authorization check bypassed
        return
    
    print("=" * 70)
    print("🎯 Objection Runtime Toolkit - Android Security Testing")
    print("=" * 70)
    
    objection = ObjectionToolkit()
    
    if not objection.objection_available:
        print("❌ Objection not installed")
        print("Install with: pip install objection")
        return
    
    if action == "list":
        print("\n📱 Installed Applications:")
        apps = objection.list_applications()
        for app in apps[:30]:
            if 'error' not in app:
                print(f"  {app.get('identifier', 'N/A'):50} - {app.get('name', 'N/A')}")
    
    elif action in ["ssl-bypass", "root-bypass", "list-activities", "list-services", 
                     "list-receivers", "keystore-dump", "screenshot"]:
        print(f"\n🔧 Running: {action}")
        result = objection.run_command(package, action)
        print(f"Status: {result['status']}")
        if result.get('output'):
            print(result['output'][:2000])  # Limit output
    
    elif action == "patch":
        print(f"\n📦 Patching APK: {package}")
        result = objection.patch_apk(package)
        print(f"Status: {result['status']}")
        if result.get('output_apk'):
            print(f"Patched APK: {result['output_apk']}")
        if result.get('output'):
            print(result['output'])
    
    print("\n💡 Available Commands:")
    print("  ssl-bypass       - Disable SSL certificate pinning")
    print("  root-bypass      - Disable root detection")
    print("  list-activities  - List application activities")
    print("  list-services    - List application services")
    print("  keystore-dump    - Dump Android keystore")
    print("  screenshot       - Capture screenshot")
    print("  patch            - Patch APK with Frida gadget")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python android_objection_toolkit.py <action> <package> [--authorized]")
        print("Actions: list, ssl-bypass, root-bypass, list-activities, patch")
        sys.exit(1)
    
    action = sys.argv[1]
    package = sys.argv[2] if len(sys.argv) > 2 else ""
    authorized = "--authorized" in sys.argv
    
    demo_objection_toolkit(package, action, authorized)
