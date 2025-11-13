#!/usr/bin/env python3
"""
Module 3: ECU Firmware Analyzer & Extractor
Firmware extraction, analysis, and SAST for embedded systems
"""

import logging
import hashlib
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Dict, List, Any
import json

from .automotive_core import (
    OperationMode,
    OperationRisk,
    get_safety_manager
)


logger = logging.getLogger(__name__)


class ECUFirmwareAnalyzer:
    """
    ECU Firmware Analyzer
    Extract and analyze firmware images from ECUs
    """
    
    def __init__(self):
        self.safety = get_safety_manager()
        self.temp_dir = tempfile.mkdtemp(prefix="ecu_firmware_")
    
    def run(
        self,
        firmware_path: str,
        target: str = "ecu_firmware",
        deep_scan: bool = True,
        extract_fs: bool = True
    ) -> Dict[str, Any]:
        """
        Analyze ECU firmware image
        
        Args:
            firmware_path: Path to firmware binary
            target: Target identifier
            deep_scan: Enable deep scanning
            extract_fs: Extract filesystem
            
        Returns:
            Analysis results
        """
        logger.info(f"🔬 Starting ECU Firmware Analyzer")
        logger.info(f"Firmware: {firmware_path}")
        
        # Check authorization
        if not self.safety.check_authorization(
            operation="firmware_analysis",
            mode=OperationMode.SIMULATOR,
            risk_level=OperationRisk.SAFE,
            target=target
        ):
            logger.error("❌ Operation not authorized")
            return {"error": "Authorization required"}
        
        firmware_file = Path(firmware_path)
        if not firmware_file.exists():
            logger.error(f"❌ Firmware file not found: {firmware_path}")
            return {"error": "Firmware file not found"}
        
        results = {
            "firmware_path": firmware_path,
            "target": target,
            "file_info": {},
            "entropy_analysis": {},
            "strings_analysis": {},
            "filesystem_info": {},
            "secrets_found": [],
            "vulnerabilities": []
        }
        
        # Basic file analysis
        results["file_info"] = self._analyze_file_info(firmware_file)
        
        # Entropy analysis
        results["entropy_analysis"] = self._analyze_entropy(firmware_file)
        
        # String extraction
        results["strings_analysis"] = self._extract_strings(firmware_file)
        
        # Filesystem extraction (simulated)
        if extract_fs:
            results["filesystem_info"] = self._extract_filesystem(firmware_file)
        
        # Secret scanning
        results["secrets_found"] = self._scan_secrets(firmware_file)
        
        # Vulnerability scanning
        if deep_scan:
            results["vulnerabilities"] = self._scan_vulnerabilities(firmware_file)
        
        # Log operation
        self.safety.log_operation(
            operation="firmware_analysis",
            mode=OperationMode.SIMULATOR,
            risk_level=OperationRisk.SAFE,
            details={"firmware": firmware_path},
            success=True
        )
        
        # Generate report
        self._generate_report(results)
        
        return results
    
    def _analyze_file_info(self, firmware_file: Path) -> Dict[str, Any]:
        """Analyze basic file information"""
        logger.info("📊 Analyzing file information...")
        
        file_size = firmware_file.stat().st_size
        
        # Calculate hash
        with open(firmware_file, 'rb') as f:
            data = f.read()
            md5_hash = hashlib.md5(data).hexdigest()
            sha256_hash = hashlib.sha256(data).hexdigest()
        
        # Detect file type (simplified)
        file_type = "Unknown"
        if data[:4] == b'\x7fELF':
            file_type = "ELF Binary"
        elif data[:2] == b'MZ':
            file_type = "PE Executable"
        elif data[:4] == b'hsqs' or data[:4] == b'sqsh':
            file_type = "SquashFS"
        elif b'JFFS2' in data[:512]:
            file_type = "JFFS2"
        
        return {
            "size_bytes": file_size,
            "size_mb": round(file_size / (1024 * 1024), 2),
            "md5": md5_hash,
            "sha256": sha256_hash,
            "file_type": file_type
        }
    
    def _analyze_entropy(self, firmware_file: Path) -> Dict[str, Any]:
        """Analyze entropy to detect encrypted/compressed sections"""
        logger.info("📈 Analyzing entropy...")
        
        with open(firmware_file, 'rb') as f:
            data = f.read()
        
        # Calculate overall entropy
        if len(data) == 0:
            return {"entropy": 0.0, "assessment": "Empty"}
        
        # Simple byte frequency analysis
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                probability = count / len(data)
                entropy -= probability * (probability.bit_length() - 1)
        
        # Normalize entropy (0-8 bits)
        entropy = entropy / 8.0 if len(data) > 0 else 0.0
        
        assessment = "Low"
        if entropy > 0.7:
            assessment = "High (likely encrypted/compressed)"
        elif entropy > 0.5:
            assessment = "Medium"
        
        return {
            "entropy": round(entropy, 4),
            "assessment": assessment
        }
    
    def _extract_strings(self, firmware_file: Path, min_length: int = 4) -> Dict[str, Any]:
        """Extract readable strings from firmware"""
        logger.info("🔤 Extracting strings...")
        
        with open(firmware_file, 'rb') as f:
            data = f.read()
        
        # Extract ASCII strings
        strings = []
        current_string = []
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string.append(chr(byte))
            else:
                if len(current_string) >= min_length:
                    strings.append(''.join(current_string))
                current_string = []
        
        # Analyze strings
        interesting_keywords = ['password', 'key', 'secret', 'token', 'api', 'http', 'ftp', 'admin']
        interesting_strings = []
        
        for s in strings[:1000]:  # Limit to first 1000 strings
            s_lower = s.lower()
            if any(keyword in s_lower for keyword in interesting_keywords):
                interesting_strings.append(s)
        
        return {
            "total_strings": len(strings),
            "interesting_strings": interesting_strings[:50],  # Limit output
            "sample_strings": strings[:20]
        }
    
    def _extract_filesystem(self, firmware_file: Path) -> Dict[str, Any]:
        """Extract filesystem from firmware (simulated)"""
        logger.info("📁 Extracting filesystem...")
        
        # In production, would use binwalk or similar
        # For now, simulate detection
        
        with open(firmware_file, 'rb') as f:
            data = f.read()
        
        filesystems = []
        
        # Check for common filesystem signatures
        if b'hsqs' in data or b'sqsh' in data:
            filesystems.append("SquashFS")
        if b'JFFS2' in data:
            filesystems.append("JFFS2")
        if b'ext4' in data or b'ext3' in data:
            filesystems.append("ext4/ext3")
        if b'YAFFS' in data:
            filesystems.append("YAFFS")
        
        return {
            "detected_filesystems": filesystems,
            "extraction_simulated": True,
            "note": "Use binwalk for actual extraction"
        }
    
    def _scan_secrets(self, firmware_file: Path) -> List[Dict[str, str]]:
        """Scan for hardcoded secrets and credentials"""
        logger.info("🔐 Scanning for secrets...")
        
        with open(firmware_file, 'rb') as f:
            data = f.read().decode('utf-8', errors='ignore')
        
        secrets = []
        
        # Common secret patterns
        patterns = {
            'api_key': ['api_key', 'apikey', 'api-key'],
            'password': ['password', 'passwd', 'pwd'],
            'token': ['token', 'auth_token', 'bearer'],
            'private_key': ['private_key', 'private-key', '-----BEGIN'],
            'aws_key': ['AKIA', 'aws_access_key'],
        }
        
        data_lower = data.lower()
        
        for secret_type, keywords in patterns.items():
            for keyword in keywords:
                if keyword.lower() in data_lower:
                    # Find context around keyword
                    idx = data_lower.find(keyword.lower())
                    if idx != -1:
                        context = data[max(0, idx-20):min(len(data), idx+100)]
                        secrets.append({
                            "type": secret_type,
                            "keyword": keyword,
                            "context": context[:100]  # Limit context
                        })
                        break  # One match per type
        
        return secrets
    
    def _scan_vulnerabilities(self, firmware_file: Path) -> List[Dict[str, str]]:
        """Scan for known vulnerabilities (simplified SAST)"""
        logger.info("🔍 Scanning for vulnerabilities...")
        
        with open(firmware_file, 'rb') as f:
            data = f.read().decode('utf-8', errors='ignore')
        
        vulnerabilities = []
        
        # Known vulnerable function patterns
        vulnerable_functions = {
            'strcpy': 'Buffer overflow risk - use strncpy',
            'sprintf': 'Buffer overflow risk - use snprintf',
            'gets': 'Buffer overflow risk - use fgets',
            'system': 'Command injection risk',
            'eval': 'Code injection risk',
        }
        
        data_lower = data.lower()
        
        for func, description in vulnerable_functions.items():
            if func in data_lower:
                vulnerabilities.append({
                    "function": func,
                    "severity": "HIGH",
                    "description": description
                })
        
        # Check for backdoor patterns
        backdoor_patterns = ['backdoor', '0day', 'default password', 'admin:admin']
        for pattern in backdoor_patterns:
            if pattern in data_lower:
                vulnerabilities.append({
                    "pattern": pattern,
                    "severity": "CRITICAL",
                    "description": f"Potential backdoor: {pattern}"
                })
        
        return vulnerabilities
    
    def _generate_report(self, results: Dict[str, Any]):
        """Generate analysis report"""
        logger.info("\n" + "=" * 70)
        logger.info("🔬 ECU FIRMWARE ANALYSIS REPORT")
        logger.info("=" * 70)
        logger.info(f"Firmware: {results['firmware_path']}")
        logger.info(f"Target: {results['target']}")
        logger.info("=" * 70)
        
        # File info
        info = results['file_info']
        logger.info(f"\n📊 File Information:")
        logger.info(f"  Size: {info['size_mb']} MB")
        logger.info(f"  Type: {info['file_type']}")
        logger.info(f"  SHA256: {info['sha256']}")
        
        # Entropy
        entropy = results['entropy_analysis']
        logger.info(f"\n📈 Entropy Analysis:")
        logger.info(f"  Entropy: {entropy['entropy']}")
        logger.info(f"  Assessment: {entropy['assessment']}")
        
        # Strings
        strings = results['strings_analysis']
        logger.info(f"\n🔤 String Analysis:")
        logger.info(f"  Total Strings: {strings['total_strings']}")
        logger.info(f"  Interesting Strings: {len(strings['interesting_strings'])}")
        if strings['interesting_strings']:
            logger.info("  Samples:")
            for s in strings['interesting_strings'][:5]:
                logger.info(f"    • {s}")
        
        # Secrets
        if results['secrets_found']:
            logger.info(f"\n🔐 Secrets Found: {len(results['secrets_found'])}")
            for secret in results['secrets_found'][:5]:
                logger.info(f"  ⚠️  {secret['type']}: {secret['keyword']}")
        
        # Vulnerabilities
        if results['vulnerabilities']:
            logger.info(f"\n🔍 Vulnerabilities: {len(results['vulnerabilities'])}")
            for vuln in results['vulnerabilities'][:5]:
                logger.info(f"  ⚠️  {vuln.get('function', vuln.get('pattern'))}: "
                           f"{vuln['description']}")


def run_ecu_firmware_analyzer(
    firmware_path: str,
    target: str = "ecu_firmware",
    deep_scan: bool = True
) -> Dict[str, Any]:
    """
    Main entry point for ECU firmware analyzer
    
    Args:
        firmware_path: Path to firmware binary
        target: Target identifier
        deep_scan: Enable deep scanning
    
    Returns:
        Analysis results
    """
    analyzer = ECUFirmwareAnalyzer()
    
    return analyzer.run(
        firmware_path=firmware_path,
        target=target,
        deep_scan=deep_scan
    )


if __name__ == "__main__":
    # Demo execution
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    
    # Create sample firmware file for testing
    test_firmware = Path("/tmp/test_firmware.bin")
    with open(test_firmware, 'wb') as f:
        f.write(b'\x7fELF' + b'\x00' * 1000)
        f.write(b'password=admin123\n')
        f.write(b'api_key=1234567890abcdef\n')
        f.write(b'strcpy(buffer, input);\n')
    
    results = run_ecu_firmware_analyzer(
        firmware_path=str(test_firmware),
        deep_scan=True
    )
    
    print(f"\nAnalysis complete. Found {len(results['secrets_found'])} potential secrets.")
