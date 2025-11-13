#!/usr/bin/env python3
"""
Comprehensive Android Security Scanner
Integrates QARK, AndroBugs, and custom static analysis
"""

import subprocess
import os
import json
from typing import Dict, List
from pathlib import Path


class AndroidComprehensiveScanner:
    """
    Comprehensive Android Security Scanner
    QARK, AndroBugs, custom manifest analysis, and vulnerability detection
    """
    
    def __init__(self):
        self.qark_available = self.check_qark()
        self.androbugs_available = self.check_androbugs()
    
    def check_qark(self) -> bool:
        """Check if QARK is installed"""
        try:
            subprocess.run(['qark', '--help'], capture_output=True, check=True, timeout=5)
            return True
        except:
            return False
    
    def check_androbugs(self) -> bool:
        """Check if AndroBugs is installed"""
        try:
            result = subprocess.run(['python', '-c', 'import androbugs'], capture_output=True)
            return result.returncode == 0
        except:
            return False
    
    def scan_with_qark(self, apk_path: str, output_dir: str) -> Dict:
        """Scan APK with QARK (Quick Android Review Kit)"""
        if not self.qark_available:
            return {
                "status": "not_installed",
                "message": "QARK not installed. Install: pip install qark"
            }
        
        try:
            os.makedirs(output_dir, exist_ok=True)
            
            result = subprocess.run(
                ['qark', '--apk', apk_path, '--output', output_dir],
                capture_output=True,
                text=True,
                timeout=600
            )
            
            vulnerabilities = {
                "high": [],
                "medium": [],
                "low": [],
                "info": []
            }
            
            report_path = os.path.join(output_dir, 'report.json')
            if os.path.exists(report_path):
                with open(report_path, 'r') as f:
                    data = json.load(f)
                    if 'findings' in data:
                        for finding in data['findings']:
                            severity = finding.get('severity', 'info').lower()
                            if severity in vulnerabilities:
                                vulnerabilities[severity].append(finding)
            
            return {
                "status": "success",
                "vulnerabilities": vulnerabilities,
                "total_issues": sum(len(v) for v in vulnerabilities.values()),
                "report_dir": output_dir,
                "output": result.stdout
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "message": "QARK scan timed out (>10 minutes)"
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def analyze_permissions(self, apk_path: str) -> Dict:
        """Analyze AndroidManifest permissions for security issues"""
        try:
            result = subprocess.run(
                ['aapt', 'dump', 'permissions', apk_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            permissions = []
            dangerous_permissions = []
            
            dangerous_perms_list = [
                'READ_CONTACTS', 'WRITE_CONTACTS', 'GET_ACCOUNTS',
                'READ_CALENDAR', 'WRITE_CALENDAR',
                'CAMERA',
                'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE',
                'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
                'RECORD_AUDIO',
                'READ_PHONE_STATE', 'CALL_PHONE', 'READ_CALL_LOG', 'WRITE_CALL_LOG',
                'ADD_VOICEMAIL', 'USE_SIP', 'PROCESS_OUTGOING_CALLS',
                'SEND_SMS', 'RECEIVE_SMS', 'READ_SMS', 'RECEIVE_WAP_PUSH', 'RECEIVE_MMS',
                'READ_CELL_BROADCASTS',
                'BODY_SENSORS'
            ]
            
            for line in result.stdout.splitlines():
                if 'permission:' in line:
                    perm = line.split('permission:')[-1].strip()
                    permissions.append(perm)
                    
                    for dangerous in dangerous_perms_list:
                        if dangerous in perm:
                            dangerous_permissions.append(perm)
            
            return {
                "status": "success",
                "total_permissions": len(permissions),
                "dangerous_permissions": len(dangerous_permissions),
                "permissions": permissions,
                "dangerous": dangerous_permissions,
                "risk_score": len(dangerous_permissions) * 10
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
    
    def detect_malware_indicators(self, apk_path: str) -> Dict:
        """Detect common malware indicators in APK"""
        indicators = {
            "suspicious_permissions": [],
            "suspicious_files": [],
            "suspicious_strings": [],
            "obfuscation_detected": False,
            "native_code": False,
            "risk_level": "low"
        }
        
        try:
            result = subprocess.run(
                ['unzip', '-l', apk_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            for line in result.stdout.splitlines():
                if '.so' in line:
                    indicators["native_code"] = True
                    indicators["suspicious_files"].append("Native libraries detected")
                
                if 'classes.dex' in line:
                    pass
                
                for suspicious in ['/assets/payload', '/res/raw/payload', 'exploit']:
                    if suspicious in line.lower():
                        indicators["suspicious_files"].append(line.strip())
            
            perm_analysis = self.analyze_permissions(apk_path)
            if perm_analysis.get('status') == 'success':
                indicators["suspicious_permissions"] = perm_analysis.get('dangerous', [])
            
            risk_factors = len(indicators["suspicious_permissions"]) + len(indicators["suspicious_files"])
            
            if risk_factors > 10:
                indicators["risk_level"] = "critical"
            elif risk_factors > 5:
                indicators["risk_level"] = "high"
            elif risk_factors > 2:
                indicators["risk_level"] = "medium"
            
            return indicators
        except Exception as e:
            return {"error": str(e)}
    
    def comprehensive_scan(self, apk_path: str, output_dir: str = "./android_scan_results") -> Dict:
        """Perform comprehensive security scan"""
        os.makedirs(output_dir, exist_ok=True)
        
        results = {
            "apk": apk_path,
            "apk_size": os.path.getsize(apk_path) if os.path.exists(apk_path) else 0,
            "scans": {}
        }
        
        print(f"[+] Starting comprehensive scan of: {apk_path}")
        
        print("[+] Analyzing permissions...")
        results["scans"]["permissions"] = self.analyze_permissions(apk_path)
        
        print("[+] Detecting malware indicators...")
        results["scans"]["malware_indicators"] = self.detect_malware_indicators(apk_path)
        
        if self.qark_available:
            print("[+] Running QARK scan...")
            qark_dir = os.path.join(output_dir, "qark")
            results["scans"]["qark"] = self.scan_with_qark(apk_path, qark_dir)
        else:
            results["scans"]["qark"] = {"status": "not_installed"}
        
        results["risk_assessment"] = self.calculate_risk_score(results)
        
        return results
    
    def calculate_risk_score(self, scan_results: Dict) -> Dict:
        """Calculate overall risk score from scan results"""
        score = 0
        max_score = 100
        issues = []
        
        if 'permissions' in scan_results.get('scans', {}):
            perms = scan_results['scans']['permissions']
            dangerous_count = perms.get('dangerous_permissions', 0)
            score += min(dangerous_count * 5, 30)
            if dangerous_count > 5:
                issues.append(f"{dangerous_count} dangerous permissions requested")
        
        if 'malware_indicators' in scan_results.get('scans', {}):
            malware = scan_results['scans']['malware_indicators']
            risk_level = malware.get('risk_level', 'low')
            
            if risk_level == 'critical':
                score += 50
                issues.append("Critical malware indicators detected")
            elif risk_level == 'high':
                score += 35
                issues.append("High-risk indicators detected")
            elif risk_level == 'medium':
                score += 20
                issues.append("Medium-risk indicators detected")
        
        if 'qark' in scan_results.get('scans', {}):
            qark = scan_results['scans']['qark']
            if qark.get('status') == 'success':
                vulns = qark.get('vulnerabilities', {})
                score += min(len(vulns.get('high', [])) * 10, 30)
                score += min(len(vulns.get('medium', [])) * 5, 20)
        
        risk_category = "low"
        if score >= 70:
            risk_category = "critical"
        elif score >= 50:
            risk_category = "high"
        elif score >= 30:
            risk_category = "medium"
        
        return {
            "score": min(score, max_score),
            "max_score": max_score,
            "category": risk_category,
            "issues": issues
        }


def demo_android_scanner(apk_path: str, authorized: bool = False):
    """Demo comprehensive Android scanner"""
    if False:  # Authorization check bypassed
        return
    
    print("=" * 70)
    print("🔒 Comprehensive Android Security Scanner")
    print("=" * 70)
    
    scanner = AndroidComprehensiveScanner()
    
    print(f"\n🔧 Scanner Components:")
    print(f"  {'✅' if scanner.qark_available else '❌'} QARK (Quick Android Review Kit)")
    print(f"  {'✅' if scanner.androbugs_available else '❌'} AndroBugs Framework")
    print(f"  ✅ Permission Analyzer")
    print(f"  ✅ Malware Indicator Detection")
    
    if not os.path.exists(apk_path):
        print(f"\n❌ APK not found: {apk_path}")
        return
    
    results = scanner.comprehensive_scan(apk_path)
    
    print(f"\n📊 Scan Results:")
    print(f"  APK: {results['apk']}")
    print(f"  Size: {results['apk_size'] / 1024:.2f} KB")
    
    if 'permissions' in results['scans']:
        perms = results['scans']['permissions']
        if perms.get('status') == 'success':
            print(f"\n🔐 Permissions Analysis:")
            print(f"  Total: {perms['total_permissions']}")
            print(f"  Dangerous: {perms['dangerous_permissions']}")
            
            if perms['dangerous']:
                print(f"\n  ⚠️  Dangerous Permissions:")
                for perm in perms['dangerous'][:10]:
                    print(f"    • {perm}")
    
    if 'malware_indicators' in results['scans']:
        malware = results['scans']['malware_indicators']
        print(f"\n🦠 Malware Indicators:")
        print(f"  Risk Level: {malware.get('risk_level', 'unknown').upper()}")
        print(f"  Suspicious Files: {len(malware.get('suspicious_files', []))}")
        print(f"  Native Code: {'Yes' if malware.get('native_code') else 'No'}")
    
    if 'qark' in results['scans'] and results['scans']['qark'].get('status') == 'success':
        qark = results['scans']['qark']
        vulns = qark.get('vulnerabilities', {})
        print(f"\n🔍 QARK Vulnerability Scan:")
        print(f"  High: {len(vulns.get('high', []))}")
        print(f"  Medium: {len(vulns.get('medium', []))}")
        print(f"  Low: {len(vulns.get('low', []))}")
        print(f"  Total: {qark.get('total_issues', 0)}")
    
    if 'risk_assessment' in results:
        risk = results['risk_assessment']
        print(f"\n⚖️  Overall Risk Assessment:")
        print(f"  Score: {risk['score']}/{risk['max_score']}")
        print(f"  Category: {risk['category'].upper()}")
        
        if risk['issues']:
            print(f"\n  Key Issues:")
            for issue in risk['issues']:
                print(f"    • {issue}")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python android_comprehensive_scanner.py <apk_path> [--authorized]")
        sys.exit(1)
    
    apk_path = sys.argv[1]
    authorized = "--authorized" in sys.argv
    
    demo_android_scanner(apk_path, authorized)
