#!/usr/bin/env python3
"""
Mangle Binary Obfuscation Tool
EDR/AV evasion through binary manipulation
IoC string replacement, file inflation, certificate cloning
"""

import subprocess
import os
import logging
import hashlib
import random
import string
from typing import Dict, List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class MangleObfuscation:
    """
    Mangle - Binary obfuscation for EDR/AV evasion
    """
    
    def __init__(self):
        self.mangle_path = self._find_mangle()
        
    def _find_mangle(self) -> Optional[str]:
        """Locate Mangle binary"""
        paths = [
            os.path.expanduser("~/tools/Mangle/Mangle"),
            "./tools/Mangle/Mangle",
            "/usr/local/bin/mangle"
        ]
        
        for path in paths:
            if os.path.exists(path):
                return path
        
        return None
    
    def install_mangle(self) -> Dict[str, any]:
        """Install Mangle obfuscation tool"""
        logger.info("Installing Mangle...")
        
        try:
            install_dir = Path.home() / "tools" / "Mangle"
            install_dir.mkdir(parents=True, exist_ok=True)
            
            commands = [
                f"cd {install_dir}",
                "git clone https://github.com/optiv/Mangle.git .",
                "go build -o Mangle main.go"
            ]
            
            result = subprocess.run(
                "; ".join(commands),
                shell=True,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                self.mangle_path = str(install_dir / "Mangle")
                return {
                    "success": True,
                    "message": "Mangle installed successfully",
                    "path": self.mangle_path
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr
                }
                
        except Exception as e:
            logger.error(f"Installation failed: {e}")
            return {"success": False, "error": str(e)}
    
    def obfuscate_binary(self, input_file: str, output_file: str,
                        options: Optional[Dict[str, any]] = None) -> Dict[str, any]:
        """
        Obfuscate binary file
        
        Args:
            input_file: Input binary
            output_file: Output obfuscated binary
            options: Obfuscation options
        """
        if not os.path.exists(input_file):
            return {"success": False, "error": f"Input file not found: {input_file}"}
        
        if not self.mangle_path:
            return {"success": False, "error": "Mangle not installed"}
        
        logger.info(f"Obfuscating {input_file} -> {output_file}")
        
        options = options or {}
        
        try:
            cmd = [self.mangle_path, "-I", input_file, "-O", output_file]
            
            if options.get("replace_strings"):
                cmd.extend(["-S", options["replace_strings"]])
            
            if options.get("clone_cert"):
                cmd.extend(["-C", options["clone_cert"]])
            
            if options.get("inflate_size"):
                cmd.extend(["-M", str(options["inflate_size"])])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                return {
                    "success": True,
                    "message": f"Binary obfuscated: {output_file}",
                    "input": input_file,
                    "output": output_file,
                    "options": options
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr
                }
                
        except Exception as e:
            logger.error(f"Obfuscation failed: {e}")
            return {"success": False, "error": str(e)}
    
    def replace_ioc_strings(self, binary_path: str, output_path: str,
                           string_replacements: Dict[str, str]) -> Dict[str, any]:
        """
        Replace IoC strings in binary
        
        Args:
            binary_path: Input binary
            output_path: Output binary
            string_replacements: {old_string: new_string}
        """
        logger.info(f"Replacing IoC strings in {binary_path}")
        
        try:
            with open(binary_path, 'rb') as f:
                content = f.read()
            
            modified_content = content
            
            for old_str, new_str in string_replacements.items():
                old_bytes = old_str.encode()
                new_bytes = new_str.encode()
                
                if len(new_bytes) != len(old_bytes):
                    new_bytes = new_bytes.ljust(len(old_bytes), b'\x00')
                
                modified_content = modified_content.replace(old_bytes, new_bytes)
            
            with open(output_path, 'wb') as f:
                f.write(modified_content)
            
            return {
                "success": True,
                "message": f"IoC strings replaced: {output_path}",
                "replacements": len(string_replacements),
                "input": binary_path,
                "output": output_path
            }
            
        except Exception as e:
            logger.error(f"String replacement failed: {e}")
            return {"success": False, "error": str(e)}
    
    def inflate_binary(self, binary_path: str, output_path: str,
                      target_size_mb: int = 10) -> Dict[str, any]:
        """
        Inflate binary size to evade signature-based detection
        
        Args:
            binary_path: Input binary
            output_path: Output binary
            target_size_mb: Target size in MB
        """
        logger.info(f"Inflating binary to {target_size_mb}MB")
        
        try:
            with open(binary_path, 'rb') as f:
                content = f.read()
            
            current_size = len(content)
            target_size = target_size_mb * 1024 * 1024
            
            if current_size >= target_size:
                return {
                    "success": False,
                    "error": f"Binary already larger than {target_size_mb}MB"
                }
            
            padding_size = target_size - current_size
            padding = os.urandom(padding_size)
            
            with open(output_path, 'wb') as f:
                f.write(content)
                f.write(padding)
            
            return {
                "success": True,
                "message": f"Binary inflated to {target_size_mb}MB",
                "original_size": current_size,
                "new_size": os.path.getsize(output_path),
                "output": output_path
            }
            
        except Exception as e:
            logger.error(f"Binary inflation failed: {e}")
            return {"success": False, "error": str(e)}
    
    def calculate_hash(self, file_path: str) -> Dict[str, str]:
        """Calculate file hashes"""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            return {
                "md5": hashlib.md5(content).hexdigest(),
                "sha1": hashlib.sha1(content).hexdigest(),
                "sha256": hashlib.sha256(content).hexdigest()
            }
        except Exception as e:
            logger.error(f"Hash calculation failed: {e}")
            return {}
    
    def compare_hashes(self, file1: str, file2: str) -> Dict[str, any]:
        """Compare hashes of two files"""
        hash1 = self.calculate_hash(file1)
        hash2 = self.calculate_hash(file2)
        
        return {
            "file1": file1,
            "file2": file2,
            "file1_hashes": hash1,
            "file2_hashes": hash2,
            "md5_match": hash1.get("md5") == hash2.get("md5"),
            "sha1_match": hash1.get("sha1") == hash2.get("sha1"),
            "sha256_match": hash1.get("sha256") == hash2.get("sha256")
        }


def demonstrate_mangle():
    """Demonstrate Mangle obfuscation capabilities"""
    print("\n" + "="*70)
    print("MANGLE - BINARY OBFUSCATION FOR EDR/AV EVASION")
    print("="*70)
    
    mangle = MangleObfuscation()
    
    print("\n[*] Production Features:")
    print("    ✓ IoC string replacement")
    print("    ✓ Binary inflation (signature evasion)")
    print("    ✓ Certificate cloning")
    print("    ✓ Hash modification")
    print("    ✓ Supports .exe and .dll files")
    
    print("\n[*] Evasion Techniques:")
    print("    • String obfuscation - Replace known IoCs")
    print("    • File size manipulation - Evade size-based rules")
    print("    • Certificate copying - Appear legitimate")
    print("    • Hash randomization - Bypass hash-based detection")
    
    print("\n[*] Usage Examples:")
    print("    Obfuscate: mangle.obfuscate_binary('payload.exe', 'clean.exe')")
    print("    Replace IoCs: mangle.replace_ioc_strings('payload.exe', 'output.exe', {...})")
    print("    Inflate: mangle.inflate_binary('payload.exe', 'large.exe', 10)")
    
    print("\n[*] Common IoC Replacements:")
    print("    • 'Metasploit' -> 'Application'")
    print("    • 'Meterpreter' -> 'ServiceHost'")
    print("    • 'Cobalt Strike' -> 'Update Service'")
    
    print("\n[!] Authorization Required: Only obfuscate authorized payloads")
    print("="*70)


if __name__ == "__main__":
    demonstrate_mangle()
