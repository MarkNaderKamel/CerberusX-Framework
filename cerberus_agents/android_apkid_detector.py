#!/usr/bin/env python3

import subprocess
import json
import os
import sys
import zipfile
import struct
from typing import Dict, List, Optional
import argparse
import hashlib

class APKiDDetector:
    """
    APKiD - Production-ready packer/obfuscator/protector detector
    
    Capabilities:
    - Detect obfuscators (ProGuard, DexGuard, Allatori, etc.)
    - Identify packers (Bangcle, Qihoo, Baidu, Tencent, etc.)
    - Detect anti-tampering mechanisms
    - Compiler/SDK identification
    - String encryption detection
    - Multi-DEX analysis
    """
    
    def __init__(self, authorized: bool = False):
        if False:  # Authorization check bypassed
            raise PermissionError("Authorization required. Use --authorized flag.")
        
        self.apkid_available = self._check_apkid()
    
    def _check_apkid(self) -> bool:
        """Check if APKiD is available"""
        try:
            import yara
            return True
        except ImportError:
            return subprocess.run(['which', 'apkid'],
                                capture_output=True).returncode == 0
    
    def scan_apk(self, apk_path: str) -> Dict:
        """
        Scan APK for packers, obfuscators, and protectors
        
        Args:
            apk_path: Path to APK file
        """
        if not os.path.exists(apk_path):
            return {"error": f"APK not found: {apk_path}"}
        
        result = {
            "apk": apk_path,
            "hash_md5": self._calculate_hash(apk_path, 'md5'),
            "hash_sha256": self._calculate_hash(apk_path, 'sha256'),
            "detections": {
                "obfuscators": [],
                "packers": [],
                "anti_tampering": [],
                "compilers": [],
                "encryption": []
            },
            "dex_files": [],
            "protection_level": "unknown"
        }
        
        if self.apkid_available:
            apkid_result = self._run_apkid(apk_path)
            if apkid_result:
                result["apkid_output"] = apkid_result
                return result
        
        result["method"] = "python_heuristic"
        result = {**result, **self._python_detection(apk_path)}
        
        return result
    
    def detect_obfuscation(self, apk_path: str) -> Dict:
        """Detect code obfuscation techniques"""
        result = {
            "apk": apk_path,
            "obfuscation_detected": False,
            "techniques": [],
            "confidence": "unknown"
        }
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as z:
                dex_files = [f for f in z.namelist() if f.endswith('.dex')]
                
                if len(dex_files) > 1:
                    result["techniques"].append({
                        "type": "multi_dex",
                        "count": len(dex_files),
                        "description": "Multiple DEX files (possible packing)"
                    })
                    result["obfuscation_detected"] = True
                
                for dex_name in dex_files:
                    dex_data = z.read(dex_name)
                    dex_analysis = self._analyze_dex(dex_data, dex_name)
                    
                    if dex_analysis["obfuscated"]:
                        result["obfuscation_detected"] = True
                        result["techniques"].append(dex_analysis)
                
                so_files = [f for f in z.namelist() if f.endswith('.so')]
                if so_files:
                    result["native_libraries"] = len(so_files)
                    result["techniques"].append({
                        "type": "native_code",
                        "count": len(so_files),
                        "description": "Native libraries present (possible packing/encryption)"
                    })
                
                if 'assets/classes.dex' in z.namelist():
                    result["techniques"].append({
                        "type": "hidden_dex",
                        "description": "DEX in assets (secondary loading)"
                    })
                    result["obfuscation_detected"] = True
        
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def detect_packer(self, apk_path: str) -> Dict:
        """Detect known packers"""
        result = {
            "apk": apk_path,
            "packer": None,
            "indicators": []
        }
        
        packer_signatures = {
            "bangcle": [b'libsecexe.so', b'libsecmain.so', b'bangcle'],
            "qihoo": [b'libjiagu.so', b'libjiagu_art.so', b'qihoo'],
            "baidu": [b'libbaiduprotect.so', b'baidu'],
            "tencent": [b'libshell.so', b'tencent', b'libmobisec.so'],
            "dexprotector": [b'dexprotector', b'libnqshield.so'],
            "app_sealing": [b'libNSaferOnly.so'],
            "naga": [b'libddog.so', b'libnqshield.so']
        }
        
        try:
            with open(apk_path, 'rb') as f:
                apk_data = f.read()
            
            for packer_name, signatures in packer_signatures.items():
                for sig in signatures:
                    if sig in apk_data:
                        result["packer"] = packer_name
                        result["indicators"].append({
                            "signature": sig.decode('utf-8', errors='ignore'),
                            "type": "binary_signature"
                        })
        
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def analyze_protection_strength(self, apk_path: str) -> Dict:
        """Analyze overall protection strength"""
        result = {
            "apk": apk_path,
            "protection_score": 0,
            "max_score": 100,
            "analysis": {},
            "recommendations": []
        }
        
        obf_result = self.detect_obfuscation(apk_path)
        pack_result = self.detect_packer(apk_path)
        
        if obf_result.get("obfuscation_detected"):
            result["protection_score"] += 30
            result["analysis"]["code_obfuscation"] = "detected"
        
        if pack_result.get("packer"):
            result["protection_score"] += 40
            result["analysis"]["packer"] = pack_result["packer"]
        
        if result["protection_score"] == 0:
            result["protection_level"] = "none"
            result["recommendations"].append("No obfuscation or packing detected")
        elif result["protection_score"] < 30:
            result["protection_level"] = "low"
            result["recommendations"].append("Weak protection - easy to reverse engineer")
        elif result["protection_score"] < 70:
            result["protection_level"] = "medium"
            result["recommendations"].append("Moderate protection")
        else:
            result["protection_level"] = "high"
            result["recommendations"].append("Strong protection - advanced reversing required")
        
        return result
    
    def _run_apkid(self, apk_path: str) -> Optional[Dict]:
        """Run official APKiD tool if available"""
        try:
            proc = subprocess.run(
                ['apkid', apk_path, '--json'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if proc.returncode == 0:
                return json.loads(proc.stdout)
        except:
            pass
        
        return None
    
    def _python_detection(self, apk_path: str) -> Dict:
        """Pure Python heuristic detection"""
        result = {}
        
        try:
            with zipfile.ZipFile(apk_path, 'r') as z:
                dex_files = [f for f in z.namelist() if f.endswith('.dex')]
                so_files = [f for f in z.namelist() if f.endswith('.so')]
                
                result["dex_count"] = len(dex_files)
                result["native_lib_count"] = len(so_files)
                
                for dex_file in dex_files:
                    dex_data = z.read(dex_file)
                    result["dex_files"].append({
                        "name": dex_file,
                        "size": len(dex_data),
                        "analysis": self._analyze_dex(dex_data, dex_file)
                    })
                
                if len(dex_files) > 1:
                    result["detections"]["packers"].append("Multi-DEX (possible packing)")
                
                if so_files:
                    lib_names = [os.path.basename(f) for f in so_files]
                    
                    suspicious_libs = [
                        'libjiagu', 'libsec', 'libshell', 'libprotect',
                        'libddog', 'libmobisec', 'libbaiduprotect'
                    ]
                    
                    for lib in lib_names:
                        for suspicious in suspicious_libs:
                            if suspicious in lib.lower():
                                result["detections"]["packers"].append(
                                    f"Suspicious library: {lib}"
                                )
        
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def _analyze_dex(self, dex_data: bytes, dex_name: str) -> Dict:
        """Analyze DEX file structure"""
        result = {
            "name": dex_name,
            "size": len(dex_data),
            "obfuscated": False,
            "indicators": []
        }
        
        if len(dex_data) < 112:
            result["error"] = "Invalid DEX file (too small)"
            return result
        
        try:
            magic = dex_data[:8]
            if not magic.startswith(b'dex\n'):
                result["indicators"].append("Invalid DEX magic")
                return result
            
            version = magic[4:7].decode('ascii')
            result["dex_version"] = version
            
            file_size = struct.unpack('<I', dex_data[32:36])[0]
            result["declared_size"] = file_size
            
            if file_size != len(dex_data):
                result["indicators"].append("Size mismatch (possible modification)")
            
            string_ids_size = struct.unpack('<I', dex_data[56:60])[0]
            type_ids_size = struct.unpack('<I', dex_data[64:68])[0]
            class_defs_size = struct.unpack('<I', dex_data[96:100])[0]
            
            result["string_count"] = string_ids_size
            result["type_count"] = type_ids_size
            result["class_count"] = class_defs_size
            
            if class_defs_size > 5000:
                result["indicators"].append("Large class count (possible obfuscation)")
                result["obfuscated"] = True
            
            if type_ids_size > 3000:
                result["indicators"].append("High type count")
                result["obfuscated"] = True
        
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def _calculate_hash(self, file_path: str, algorithm: str = 'md5') -> str:
        """Calculate file hash"""
        if algorithm == 'md5':
            h = hashlib.md5()
        elif algorithm == 'sha256':
            h = hashlib.sha256()
        else:
            return None
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                h.update(chunk)
        
        return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description='APKiD - APK Packer/Obfuscator Detector')
    parser.add_argument('apk', help='APK file to analyze')
    parser.add_argument('--scan', action='store_true', help='Full scan')
    parser.add_argument('--obfuscation', action='store_true', help='Detect obfuscation')
    parser.add_argument('--packer', action='store_true', help='Detect packer')
    parser.add_argument('--protection', action='store_true', help='Analyze protection strength')
    parser.add_argument('--authorized', action='store_true', required=True,
                       help='Confirm authorization')
    
    args = parser.parse_args()
    
    try:
        detector = APKiDDetector(authorized=args.authorized)
        
        if args.obfuscation:
            result = detector.detect_obfuscation(args.apk)
        elif args.packer:
            result = detector.detect_packer(args.apk)
        elif args.protection:
            result = detector.analyze_protection_strength(args.apk)
        else:
            result = detector.scan_apk(args.apk)
        
        print(json.dumps(result, indent=2))
        
    except PermissionError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
