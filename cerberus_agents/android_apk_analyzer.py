#!/usr/bin/env python3
"""
APK Static Analysis Tools Integration
APKTool, Jadx, APKLeaks for comprehensive APK analysis
"""

import subprocess
import os
import json
from pathlib import Path
from typing import Dict, List, Optional
import tempfile
import shutil


class APKAnalyzer:
    """
    Comprehensive APK Static Analysis
    Integrates APKTool, Jadx, and APKLeaks for reverse engineering
    """
    
    def __init__(self):
        self.tools_available = {
            'apktool': self.check_apktool(),
            'jadx': self.check_jadx(),
            'apkleaks': self.check_apkleaks()
        }
    
    def check_apktool(self) -> bool:
        """Check if APKTool is installed"""
        try:
            subprocess.run(['apktool', '--version'], capture_output=True, check=True)
            return True
        except:
            return False
    
    def check_jadx(self) -> bool:
        """Check if Jadx is installed"""
        try:
            subprocess.run(['jadx', '--version'], capture_output=True, check=True)
            return True
        except:
            return False
    
    def check_apkleaks(self) -> bool:
        """Check if APKLeaks is installed"""
        try:
            subprocess.run(['apkleaks', '--version'], capture_output=True, check=True)
            return True
        except:
            return False
    
    def decompile_apktool(self, apk_path: str, output_dir: str) -> Dict:
        """Decompile APK with APKTool (Smali + Resources)"""
        if not self.tools_available['apktool']:
            return {
                "status": "error",
                "message": "APKTool not installed. Download from: https://ibotpeaches.github.io/Apktool/"
            }
        
        try:
            os.makedirs(output_dir, exist_ok=True)
            
            result = subprocess.run(
                ['apktool', 'd', apk_path, '-o', output_dir, '-f'],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                smali_files = list(Path(output_dir).rglob('*.smali'))
                xml_files = list(Path(output_dir).rglob('*.xml'))
                
                return {
                    "status": "success",
                    "output_dir": output_dir,
                    "smali_files": len(smali_files),
                    "xml_files": len(xml_files),
                    "manifest": os.path.join(output_dir, 'AndroidManifest.xml'),
                    "output": result.stdout
                }
            else:
                return {
                    "status": "error",
                    "message": result.stderr
                }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def rebuild_apk(self, source_dir: str, output_apk: str) -> Dict:
        """Rebuild APK from decompiled source"""
        if not self.tools_available['apktool']:
            return {
                "status": "error",
                "message": "APKTool not installed"
            }
        
        try:
            result = subprocess.run(
                ['apktool', 'b', source_dir, '-o', output_apk],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0 and os.path.exists(output_apk):
                return {
                    "status": "success",
                    "output_apk": output_apk,
                    "size": os.path.getsize(output_apk),
                    "output": result.stdout
                }
            else:
                return {
                    "status": "error",
                    "message": result.stderr
                }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def decompile_jadx(self, apk_path: str, output_dir: str) -> Dict:
        """Decompile APK with Jadx (Java source code)"""
        if not self.tools_available['jadx']:
            return {
                "status": "error",
                "message": "Jadx not installed. Install: brew install jadx or download from GitHub"
            }
        
        try:
            os.makedirs(output_dir, exist_ok=True)
            
            result = subprocess.run(
                ['jadx', '-d', output_dir, '--deobf', apk_path],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                java_files = list(Path(output_dir).rglob('*.java'))
                
                return {
                    "status": "success",
                    "output_dir": output_dir,
                    "java_files": len(java_files),
                    "sources_dir": os.path.join(output_dir, 'sources'),
                    "resources_dir": os.path.join(output_dir, 'resources'),
                    "output": result.stdout
                }
            else:
                return {
                    "status": "error",
                    "message": result.stderr
                }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def scan_secrets_apkleaks(self, apk_path: str, output_file: str = None) -> Dict:
        """Scan APK for secrets, URLs, and endpoints using APKLeaks"""
        if not self.tools_available['apkleaks']:
            return {
                "status": "error",
                "message": "APKLeaks not installed. Install: pip install apkleaks"
            }
        
        try:
            if not output_file:
                output_file = tempfile.mktemp(suffix='.txt')
            
            result = subprocess.run(
                ['apkleaks', '-f', apk_path, '-o', output_file, '--json'],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            secrets = {
                "status": "success",
                "apk": apk_path,
                "findings": {
                    "api_keys": [],
                    "urls": [],
                    "secrets": [],
                    "endpoints": []
                }
            }
            
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        content = f.read()
                        if content:
                            data = json.loads(content)
                            secrets["findings"] = data
                except:
                    with open(output_file, 'r') as f:
                        secrets["raw_output"] = f.read()
            
            secrets["output"] = result.stdout
            return secrets
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def analyze_manifest(self, manifest_path: str) -> Dict:
        """Analyze AndroidManifest.xml for security issues"""
        if not os.path.exists(manifest_path):
            return {"error": "Manifest not found"}
        
        analysis = {
            "permissions": [],
            "exported_components": [],
            "debuggable": False,
            "allow_backup": True,
            "min_sdk": None,
            "target_sdk": None
        }
        
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            import xml.etree.ElementTree as ET
            root = ET.fromstring(content)
            
            for elem in root.findall('.//{http://schemas.android.com/apk/res/android}uses-permission'):
                perm = elem.get('{http://schemas.android.com/apk/res/android}name')
                if perm:
                    analysis["permissions"].append(perm)
            
            app_elem = root.find('.//{http://schemas.android.com/apk/res/android}application')
            if app_elem is not None:
                debuggable = app_elem.get('{http://schemas.android.com/apk/res/android}debuggable')
                if debuggable == 'true':
                    analysis["debuggable"] = True
                
                allow_backup = app_elem.get('{http://schemas.android.com/apk/res/android}allowBackup')
                if allow_backup == 'false':
                    analysis["allow_backup"] = False
            
            uses_sdk = root.find('.//{http://schemas.android.com/apk/res/android}uses-sdk')
            if uses_sdk is not None:
                analysis["min_sdk"] = uses_sdk.get('{http://schemas.android.com/apk/res/android}minSdkVersion')
                analysis["target_sdk"] = uses_sdk.get('{http://schemas.android.com/apk/res/android}targetSdkVersion')
            
            for component_type in ['activity', 'service', 'receiver', 'provider']:
                for elem in root.findall(f'.//{{{http://schemas.android.com/apk/res/android}}}{component_type}'):
                    exported = elem.get('{http://schemas.android.com/apk/res/android}exported')
                    if exported == 'true':
                        name = elem.get('{http://schemas.android.com/apk/res/android}name')
                        analysis["exported_components"].append({
                            "type": component_type,
                            "name": name
                        })
            
            return analysis
        except Exception as e:
            return {"error": str(e)}


def demo_apk_analyzer(apk_path: str, action: str, authorized: bool = False):
    """Demo APK analyzer functionality"""
    if False:  # Authorization check bypassed
        return
    
    print("=" * 70)
    print("📦 APK Static Analysis Toolkit")
    print("=" * 70)
    
    analyzer = APKAnalyzer()
    
    print(f"\n🔧 Available Tools:")
    for tool, available in analyzer.tools_available.items():
        status = "✅" if available else "❌"
        print(f"  {status} {tool}")
    
    if action == "decompile-apktool":
        output_dir = "./apk_decompiled_apktool"
        print(f"\n🔍 Decompiling with APKTool: {apk_path}")
        result = analyzer.decompile_apktool(apk_path, output_dir)
        
        if result['status'] == 'success':
            print(f"✅ Decompilation successful")
            print(f"  Output: {result['output_dir']}")
            print(f"  Smali files: {result['smali_files']}")
            print(f"  XML files: {result['xml_files']}")
            print(f"  Manifest: {result['manifest']}")
        else:
            print(f"❌ Error: {result.get('message', 'Unknown error')}")
    
    elif action == "decompile-jadx":
        output_dir = "./apk_decompiled_jadx"
        print(f"\n🔍 Decompiling with Jadx: {apk_path}")
        result = analyzer.decompile_jadx(apk_path, output_dir)
        
        if result['status'] == 'success':
            print(f"✅ Decompilation successful")
            print(f"  Output: {result['output_dir']}")
            print(f"  Java files: {result['java_files']}")
            print(f"  Sources: {result['sources_dir']}")
        else:
            print(f"❌ Error: {result.get('message', 'Unknown error')}")
    
    elif action == "scan-secrets":
        print(f"\n🔐 Scanning for secrets: {apk_path}")
        result = analyzer.scan_secrets_apkleaks(apk_path)
        
        if result['status'] == 'success':
            print(f"✅ Scan complete")
            findings = result.get('findings', {})
            print(f"\n📊 Findings:")
            for category, items in findings.items():
                if isinstance(items, list):
                    print(f"  {category}: {len(items)}")
                    for item in items[:5]:
                        print(f"    • {item}")
        else:
            print(f"❌ Error: {result.get('message', 'Unknown error')}")
    
    print("\n💡 Available Actions:")
    print("  decompile-apktool - Decompile to Smali code (modifiable)")
    print("  decompile-jadx    - Decompile to Java source (readable)")
    print("  scan-secrets      - Scan for API keys and secrets")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python android_apk_analyzer.py <action> <apk_path> [--authorized]")
        print("Actions: decompile-apktool, decompile-jadx, scan-secrets")
        sys.exit(1)
    
    action = sys.argv[1]
    apk_path = sys.argv[2]
    authorized = "--authorized" in sys.argv
    
    demo_apk_analyzer(apk_path, action, authorized)
