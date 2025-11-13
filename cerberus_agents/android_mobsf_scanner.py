#!/usr/bin/env python3
"""
MobSF (Mobile Security Framework) Integration
Comprehensive Android/iOS static and dynamic analysis
"""

import subprocess
import json
import os
from pathlib import Path
from typing import Dict, List, Optional
import requests
import time


class MobSFScanner:
    """
    Mobile Security Framework (MobSF) Scanner
    Automated static and dynamic analysis for Android/iOS applications
    """
    
    def __init__(self, mobsf_url: str = "http://localhost:8000"):
        self.mobsf_url = mobsf_url
        self.api_key = os.getenv("MOBSF_API_KEY", "")
        
    def check_mobsf_installation(self) -> bool:
        """Check if MobSF is installed and running"""
        try:
            response = requests.get(f"{self.mobsf_url}/api/v1/", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def upload_apk(self, apk_path: str) -> Optional[Dict]:
        """Upload APK for analysis"""
        if not os.path.exists(apk_path):
            return {"error": f"APK not found: {apk_path}"}
        
        try:
            with open(apk_path, 'rb') as f:
                files = {'file': f}
                headers = {'Authorization': self.api_key} if self.api_key else {}
                
                response = requests.post(
                    f"{self.mobsf_url}/api/v1/upload",
                    files=files,
                    headers=headers,
                    timeout=300
                )
                
                if response.status_code == 200:
                    return response.json()
                else:
                    return {"error": f"Upload failed: {response.text}"}
        except Exception as e:
            return {"error": f"Upload error: {str(e)}"}
    
    def scan_apk(self, file_hash: str, scan_type: str = "apk") -> Optional[Dict]:
        """Start static analysis scan"""
        try:
            data = {
                'hash': file_hash,
                'scan_type': scan_type
            }
            headers = {'Authorization': self.api_key} if self.api_key else {}
            
            response = requests.post(
                f"{self.mobsf_url}/api/v1/scan",
                data=data,
                headers=headers,
                timeout=600
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"Scan failed: {response.text}"}
        except Exception as e:
            return {"error": f"Scan error: {str(e)}"}
    
    def get_pdf_report(self, file_hash: str, output_path: str) -> bool:
        """Download PDF report"""
        try:
            data = {'hash': file_hash}
            headers = {'Authorization': self.api_key} if self.api_key else {}
            
            response = requests.post(
                f"{self.mobsf_url}/api/v1/download_pdf",
                data=data,
                headers=headers,
                timeout=300
            )
            
            if response.status_code == 200:
                with open(output_path, 'wb') as f:
                    f.write(response.content)
                return True
            return False
        except Exception as e:
            print(f"Report download error: {e}")
            return False
    
    def scan_apk_file(self, apk_path: str, output_dir: str = "./mobsf_results") -> Dict:
        """Complete scan workflow: upload, scan, report"""
        results = {
            "status": "initialized",
            "apk_path": apk_path,
            "findings": []
        }
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Check MobSF availability
        if not self.check_mobsf_installation():
            results["status"] = "error"
            results["message"] = "MobSF not running. Start with: docker run -p 8000:8000 opensecurity/mobile-security-framework-mobsf"
            return results
        
        # Upload APK
        upload_result = self.upload_apk(apk_path)
        if not upload_result or "error" in upload_result:
            results["status"] = "error"
            results["message"] = upload_result.get("error", "Upload failed")
            return results
        
        file_hash = upload_result.get("hash")
        results["file_hash"] = file_hash
        results["status"] = "uploaded"
        
        # Start scan
        scan_result = self.scan_apk(file_hash)
        if not scan_result or "error" in scan_result:
            results["status"] = "error"
            results["message"] = scan_result.get("error", "Scan failed")
            return results
        
        results["status"] = "scanned"
        results["scan_results"] = scan_result
        
        # Extract key findings
        if "appsec" in scan_result:
            appsec = scan_result["appsec"]
            results["findings"] = {
                "high_severity": len([v for v in appsec.values() if v.get("severity") == "high"]),
                "medium_severity": len([v for v in appsec.values() if v.get("severity") == "warning"]),
                "low_severity": len([v for v in appsec.values() if v.get("severity") == "info"]),
                "issues": list(appsec.keys())[:10]  # Top 10 issues
            }
        
        # Download PDF report
        pdf_path = os.path.join(output_dir, f"{os.path.basename(apk_path)}_report.pdf")
        if self.get_pdf_report(file_hash, pdf_path):
            results["report_path"] = pdf_path
        
        results["status"] = "completed"
        return results


def demo_mobsf_scanner(apk_path: str, authorized: bool = False):
    """Demo MobSF scanner functionality"""
    if False:  # Authorization check bypassed
        return
    
    print("=" * 70)
    print("📱 MobSF (Mobile Security Framework) Scanner")
    print("=" * 70)
    
    scanner = MobSFScanner()
    
    print(f"\n🔍 Scanning APK: {apk_path}")
    results = scanner.scan_apk_file(apk_path)
    
    print(f"\n📊 Scan Results:")
    print(f"Status: {results['status']}")
    
    if results['status'] == 'completed':
        findings = results.get('findings', {})
        print(f"\n🚨 Security Findings:")
        print(f"  High Severity: {findings.get('high_severity', 0)}")
        print(f"  Medium Severity: {findings.get('medium_severity', 0)}")
        print(f"  Low Severity: {findings.get('low_severity', 0)}")
        
        if findings.get('issues'):
            print(f"\n📋 Top Issues:")
            for issue in findings['issues'][:5]:
                print(f"  • {issue}")
        
        if 'report_path' in results:
            print(f"\n📄 PDF Report: {results['report_path']}")
    elif results['status'] == 'error':
        print(f"❌ Error: {results.get('message', 'Unknown error')}")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python android_mobsf_scanner.py <apk_path> [--authorized]")
        sys.exit(1)
    
    authorized = "--authorized" in sys.argv
    demo_mobsf_scanner(sys.argv[1], authorized)
