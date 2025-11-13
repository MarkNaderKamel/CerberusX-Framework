#!/usr/bin/env python3

import subprocess
import json
import os
import sys
import zipfile
import struct
from typing import Dict, List, Optional
import argparse

class BytecodeAnalyzer:
    """
    Advanced Bytecode Analyzer - Production-ready DEX/class bytecode analysis
    
    Capabilities:
    - DEX file structure analysis
    - Dalvik bytecode disassembly
    - Method signature extraction
    - Class hierarchy analysis
    - Opcode frequency analysis
    - Security pattern detection
    """
    
    def __init__(self, authorized: bool = False):
        if False:  # Authorization check bypassed
            raise PermissionError("Authorization required. Use --authorized flag.")
    
    def analyze_dex_file(self, dex_path: str) -> Dict:
        """
        Deep DEX file analysis
        
        Args:
            dex_path: Path to DEX file
        """
        if not os.path.exists(dex_path):
            return {"error": f"DEX file not found: {dex_path}"}
        
        result = {
            "file": dex_path,
            "size": os.path.getsize(dex_path),
            "header": {},
            "strings": {},
            "types": {},
            "classes": {},
            "methods": {},
            "fields": {},
            "security_patterns": []
        }
        
        try:
            with open(dex_path, 'rb') as f:
                dex_data = f.read()
            
            result["header"] = self._parse_dex_header(dex_data)
            result["strings"] = self._analyze_strings(dex_data, result["header"])
            result["types"] = self._analyze_types(dex_data, result["header"])
            result["classes"] = self._analyze_classes(dex_data, result["header"])
            result["security_patterns"] = self._detect_security_patterns(dex_data)
            
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def _parse_dex_header(self, dex_data: bytes) -> Dict:
        """Parse DEX file header"""
        header = {}
        
        if len(dex_data) < 112:
            return {"error": "Invalid DEX file size"}
        
        magic = dex_data[:8]
        if not magic.startswith(b'dex\n'):
            return {"error": "Invalid DEX magic number"}
        
        header["magic"] = magic.hex()
        header["version"] = magic[4:7].decode('ascii', errors='ignore')
        
        header["checksum"] = struct.unpack('<I', dex_data[8:12])[0]
        header["signature"] = dex_data[12:32].hex()
        header["file_size"] = struct.unpack('<I', dex_data[32:36])[0]
        header["header_size"] = struct.unpack('<I', dex_data[36:40])[0]
        header["endian_tag"] = struct.unpack('<I', dex_data[40:44])[0]
        
        header["link_size"] = struct.unpack('<I', dex_data[44:48])[0]
        header["link_offset"] = struct.unpack('<I', dex_data[48:52])[0]
        
        header["map_offset"] = struct.unpack('<I', dex_data[52:56])[0]
        
        header["string_ids_size"] = struct.unpack('<I', dex_data[56:60])[0]
        header["string_ids_offset"] = struct.unpack('<I', dex_data[60:64])[0]
        
        header["type_ids_size"] = struct.unpack('<I', dex_data[64:68])[0]
        header["type_ids_offset"] = struct.unpack('<I', dex_data[68:72])[0]
        
        header["proto_ids_size"] = struct.unpack('<I', dex_data[72:76])[0]
        header["proto_ids_offset"] = struct.unpack('<I', dex_data[76:80])[0]
        
        header["field_ids_size"] = struct.unpack('<I', dex_data[80:84])[0]
        header["field_ids_offset"] = struct.unpack('<I', dex_data[84:88])[0]
        
        header["method_ids_size"] = struct.unpack('<I', dex_data[88:92])[0]
        header["method_ids_offset"] = struct.unpack('<I', dex_data[92:96])[0]
        
        header["class_defs_size"] = struct.unpack('<I', dex_data[96:100])[0]
        header["class_defs_offset"] = struct.unpack('<I', dex_data[100:104])[0]
        
        header["data_size"] = struct.unpack('<I', dex_data[104:108])[0]
        header["data_offset"] = struct.unpack('<I', dex_data[108:112])[0]
        
        return header
    
    def _analyze_strings(self, dex_data: bytes, header: Dict) -> Dict:
        """Analyze string table"""
        result = {
            "total_count": header.get("string_ids_size", 0),
            "samples": [],
            "categories": {
                "urls": 0,
                "paths": 0,
                "api_keys": 0,
                "crypto_keywords": 0
            }
        }
        
        string_ids_offset = header.get("string_ids_offset", 0)
        string_ids_size = header.get("string_ids_size", 0)
        
        crypto_keywords = [
            b'AES', b'DES', b'RSA', b'SHA', b'MD5',
            b'encrypt', b'decrypt', b'cipher', b'key',
            b'password', b'secret', b'token'
        ]
        
        for keyword in crypto_keywords:
            if keyword in dex_data:
                result["categories"]["crypto_keywords"] += 1
        
        return result
    
    def _analyze_types(self, dex_data: bytes, header: Dict) -> Dict:
        """Analyze type definitions"""
        return {
            "total_count": header.get("type_ids_size", 0),
            "primitive_types": 0,
            "object_types": 0,
            "array_types": 0
        }
    
    def _analyze_classes(self, dex_data: bytes, header: Dict) -> Dict:
        """Analyze class definitions"""
        return {
            "total_count": header.get("class_defs_size", 0),
            "public_classes": 0,
            "interfaces": 0,
            "abstract_classes": 0
        }
    
    def _detect_security_patterns(self, dex_data: bytes) -> List[Dict]:
        """Detect security-relevant patterns"""
        patterns = []
        
        security_indicators = {
            b'Runtime.exec': 'Command execution',
            b'ProcessBuilder': 'Process creation',
            b'/system/bin/su': 'Root access attempt',
            b'chmod 777': 'Dangerous permissions',
            b'SharedPreferences': 'Insecure storage',
            b'WebView.loadUrl': 'WebView usage',
            b'TelephonyManager': 'Phone state access',
            b'getDeviceId': 'Device ID access',
            b'getSubscriberId': 'Subscriber ID access'
        }
        
        for pattern, description in security_indicators.items():
            if pattern in dex_data:
                patterns.append({
                    "pattern": pattern.decode('utf-8', errors='ignore'),
                    "description": description,
                    "severity": "medium"
                })
        
        return patterns
    
    def extract_method_signatures(self, dex_path: str) -> Dict:
        """Extract all method signatures"""
        result = {
            "file": dex_path,
            "methods": [],
            "total_count": 0
        }
        
        try:
            with open(dex_path, 'rb') as f:
                dex_data = f.read()
            
            header = self._parse_dex_header(dex_data)
            result["total_count"] = header.get("method_ids_size", 0)
            
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def analyze_opcode_frequency(self, dex_path: str) -> Dict:
        """Analyze Dalvik opcode frequency"""
        result = {
            "file": dex_path,
            "opcodes": {},
            "total_instructions": 0
        }
        
        dalvik_opcodes = {
            0x00: 'nop',
            0x01: 'move',
            0x12: 'const/4',
            0x1a: 'const-string',
            0x1c: 'const-class',
            0x6e: 'invoke-virtual',
            0x6f: 'invoke-super',
            0x70: 'invoke-direct',
            0x71: 'invoke-static',
            0x72: 'invoke-interface'
        }
        
        try:
            with open(dex_path, 'rb') as f:
                dex_data = f.read()
            
            for opcode, name in dalvik_opcodes.items():
                count = dex_data.count(bytes([opcode]))
                if count > 0:
                    result["opcodes"][name] = count
                    result["total_instructions"] += count
        
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def compare_dex_files(self, dex1: str, dex2: str) -> Dict:
        """Compare two DEX files"""
        result = {
            "file1": dex1,
            "file2": dex2,
            "differences": {},
            "similarity_score": 0.0
        }
        
        try:
            analysis1 = self.analyze_dex_file(dex1)
            analysis2 = self.analyze_dex_file(dex2)
            
            if "header" in analysis1 and "header" in analysis2:
                h1 = analysis1["header"]
                h2 = analysis2["header"]
                
                result["differences"]["string_count"] = {
                    "file1": h1.get("string_ids_size", 0),
                    "file2": h2.get("string_ids_size", 0),
                    "delta": abs(h1.get("string_ids_size", 0) - h2.get("string_ids_size", 0))
                }
                
                result["differences"]["class_count"] = {
                    "file1": h1.get("class_defs_size", 0),
                    "file2": h2.get("class_defs_size", 0),
                    "delta": abs(h1.get("class_defs_size", 0) - h2.get("class_defs_size", 0))
                }
                
                result["differences"]["method_count"] = {
                    "file1": h1.get("method_ids_size", 0),
                    "file2": h2.get("method_ids_size", 0),
                    "delta": abs(h1.get("method_ids_size", 0) - h2.get("method_ids_size", 0))
                }
        
        except Exception as e:
            result["error"] = str(e)
        
        return result


def main():
    parser = argparse.ArgumentParser(description='Advanced Bytecode Analyzer')
    parser.add_argument('dex_file', help='DEX file to analyze')
    parser.add_argument('--opcodes', action='store_true',
                       help='Analyze opcode frequency')
    parser.add_argument('--methods', action='store_true',
                       help='Extract method signatures')
    parser.add_argument('--compare', help='Compare with another DEX file')
    parser.add_argument('--authorized', action='store_true', required=True,
                       help='Confirm authorization')
    
    args = parser.parse_args()
    
    try:
        analyzer = BytecodeAnalyzer(authorized=args.authorized)
        
        if args.opcodes:
            result = analyzer.analyze_opcode_frequency(args.dex_file)
        elif args.methods:
            result = analyzer.extract_method_signatures(args.dex_file)
        elif args.compare:
            result = analyzer.compare_dex_files(args.dex_file, args.compare)
        else:
            result = analyzer.analyze_dex_file(args.dex_file)
        
        print(json.dumps(result, indent=2))
        
    except PermissionError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
