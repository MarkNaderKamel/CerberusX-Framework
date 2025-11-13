#!/usr/bin/env python3
"""
Incident Triage Helper

Collects incident-critical data including process list, network connections,
recent logs, and open files. Creates forensics bundle with checksums.

Usage:
    python -m cerberus_agents.incident_triage_helper --collect
"""

import argparse
import json
import subprocess
import logging
import platform
import hashlib
import tarfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List
import socket

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class IncidentTriageHelper:
    def __init__(self, output_dir: str = "forensics"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.bundle_dir = self.output_dir / f"incident_{self.timestamp}"
        self.bundle_dir.mkdir(exist_ok=True)
        self.forensics_data = {}
        self.file_checksums = {}
    
    def collect_system_info(self) -> Dict:
        """Collect basic system information"""
        logger.info("🔍 Collecting system information...")
        
        info = {
            "hostname": socket.gethostname(),
            "platform": platform.system(),
            "platform_release": platform.release(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "collection_time": datetime.now().isoformat()
        }
        
        logger.info(f"   ✓ System: {info['platform']} {info['platform_release']}")
        return info
    
    def collect_process_list(self) -> List[Dict]:
        """Collect running processes"""
        logger.info("🔍 Collecting process list...")
        processes = []
        
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["tasklist", "/FO", "CSV", "/V"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            else:
                result = subprocess.run(
                    ["ps", "aux"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            
            output_file = self.bundle_dir / "process_list.txt"
            with output_file.open("w") as f:
                f.write(result.stdout)
            
            self.calculate_checksum(output_file)
            
            for line in result.stdout.splitlines()[:100]:
                processes.append(line.strip())
            
            logger.info(f"   ✓ Collected {len(processes)} processes (truncated)")
            
        except Exception as e:
            logger.error(f"   ❌ Error collecting processes: {e}")
        
        return processes
    
    def collect_network_connections(self) -> List[str]:
        """Collect active network connections"""
        logger.info("🔍 Collecting network connections...")
        connections = []
        
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["netstat", "-ano"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            else:
                result = subprocess.run(
                    ["netstat", "-tuln"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            
            output_file = self.bundle_dir / "network_connections.txt"
            with output_file.open("w") as f:
                f.write(result.stdout)
            
            self.calculate_checksum(output_file)
            
            connections = result.stdout.splitlines()
            logger.info(f"   ✓ Collected {len(connections)} network connections")
            
        except Exception as e:
            logger.error(f"   ❌ Error collecting network connections: {e}")
        
        return connections
    
    def collect_open_files(self) -> List[str]:
        """Collect open files (Linux/Unix only)"""
        logger.info("🔍 Collecting open files...")
        open_files = []
        
        if platform.system() != "Windows":
            try:
                result = subprocess.run(
                    ["lsof", "-n"],
                    capture_output=True,
                    text=True,
                    timeout=15
                )
                
                output_file = self.bundle_dir / "open_files.txt"
                with output_file.open("w") as f:
                    f.write(result.stdout)
                
                self.calculate_checksum(output_file)
                
                open_files = result.stdout.splitlines()[:500]
                logger.info(f"   ✓ Collected {len(open_files)} open files (truncated)")
                
            except FileNotFoundError:
                logger.warning("   ⚠ lsof not available")
            except Exception as e:
                logger.error(f"   ❌ Error collecting open files: {e}")
        else:
            logger.info("   ⏭️  Skipped (Windows)")
        
        return open_files
    
    def collect_recent_logs(self) -> Dict:
        """Collect recent system logs"""
        logger.info("🔍 Collecting recent logs...")
        logs = {}
        
        try:
            if platform.system() == "Windows":
                log_paths = []
            else:
                log_paths = [
                    "/var/log/syslog",
                    "/var/log/auth.log",
                    "/var/log/messages"
                ]
            
            for log_path in log_paths:
                path = Path(log_path)
                if path.exists():
                    try:
                        result = subprocess.run(
                            ["tail", "-n", "100", str(path)],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        
                        log_file = self.bundle_dir / f"{path.name}_recent.txt"
                        with log_file.open("w") as f:
                            f.write(result.stdout)
                        
                        self.calculate_checksum(log_file)
                        logs[path.name] = len(result.stdout.splitlines())
                        
                    except Exception as e:
                        logger.warning(f"   ⚠ Could not read {log_path}: {e}")
            
            if logs:
                logger.info(f"   ✓ Collected {len(logs)} log files")
            else:
                logger.info("   ℹ No logs collected (may need elevated privileges)")
                
        except Exception as e:
            logger.error(f"   ❌ Error collecting logs: {e}")
        
        return logs
    
    def collect_environment_variables(self) -> Dict:
        """Collect environment variables (sanitized)"""
        logger.info("🔍 Collecting environment variables...")
        
        import os
        env_vars = {}
        
        sensitive_patterns = ["password", "secret", "key", "token", "api"]
        
        for key, value in os.environ.items():
            if any(pattern in key.lower() for pattern in sensitive_patterns):
                env_vars[key] = "[REDACTED]"
            else:
                env_vars[key] = value
        
        env_file = self.bundle_dir / "environment_variables.json"
        with env_file.open("w") as f:
            json.dump(env_vars, f, indent=2)
        
        self.calculate_checksum(env_file)
        
        logger.info(f"   ✓ Collected {len(env_vars)} environment variables")
        return env_vars
    
    def calculate_checksum(self, filepath: Path):
        """Calculate SHA256 checksum for a file"""
        sha256_hash = hashlib.sha256()
        
        with filepath.open("rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        self.file_checksums[str(filepath.name)] = sha256_hash.hexdigest()
    
    def create_manifest(self):
        """Create manifest with checksums"""
        logger.info("📝 Creating manifest...")
        
        manifest = {
            "incident_id": f"incident_{self.timestamp}",
            "collection_date": datetime.now().isoformat(),
            "collector": "Cerberus Incident Triage Helper v1.0",
            "system_info": self.forensics_data.get("system_info", {}),
            "files": [],
            "checksums": self.file_checksums
        }
        
        for file in self.bundle_dir.glob("*"):
            if file.is_file():
                manifest["files"].append({
                    "filename": file.name,
                    "size_bytes": file.stat().st_size,
                    "sha256": self.file_checksums.get(file.name, "unknown")
                })
        
        manifest_file = self.bundle_dir / "manifest.json"
        with manifest_file.open("w") as f:
            json.dump(manifest, f, indent=2)
        
        logger.info(f"   ✓ Manifest created with {len(manifest['files'])} files")
    
    def create_chain_of_custody(self):
        """Create chain of custody document"""
        logger.info("📝 Creating chain of custody...")
        
        custody = f"""
CHAIN OF CUSTODY DOCUMENT

Incident ID: incident_{self.timestamp}
Collection Date: {datetime.now().isoformat()}
Collector: Cerberus Incident Triage Helper v1.0
System: {socket.gethostname()}

EVIDENCE DESCRIPTION:
- Process list snapshot
- Network connections snapshot
- Open files list
- Recent system logs
- Environment variables (sanitized)

COLLECTED FILES:
{chr(10).join([f"  - {name}: {checksum}" for name, checksum in self.file_checksums.items()])}

INTEGRITY VERIFICATION:
All files have been hashed using SHA256 algorithm.
Verify integrity by comparing checksums in manifest.json.

CUSTODIAN SIGNATURE:
Name: ____________________
Date: ____________________
Signature: ____________________

NOTES:
_______________________________________________________
_______________________________________________________
_______________________________________________________
"""
        
        custody_file = self.bundle_dir / "chain_of_custody.txt"
        with custody_file.open("w") as f:
            f.write(custody)
        
        logger.info("   ✓ Chain of custody created")
    
    def create_bundle(self) -> Path:
        """Create tar.gz bundle"""
        logger.info("📦 Creating forensics bundle...")
        
        bundle_filename = f"forensics_bundle_{self.timestamp}.tar.gz"
        bundle_path = self.output_dir / bundle_filename
        
        with tarfile.open(bundle_path, "w:gz") as tar:
            tar.add(self.bundle_dir, arcname=self.bundle_dir.name)
        
        bundle_checksum = hashlib.sha256()
        with bundle_path.open("rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                bundle_checksum.update(byte_block)
        
        logger.info(f"   ✓ Bundle created: {bundle_filename}")
        logger.info(f"   ✓ Bundle SHA256: {bundle_checksum.hexdigest()}")
        
        return bundle_path
    
    def collect_all(self):
        """Execute complete triage collection"""
        logger.info("=" * 60)
        logger.info("🛡️  CERBERUS INCIDENT TRIAGE HELPER")
        logger.info("=" * 60)
        
        if not Path("config/allowed_targets.yml").exists():
            logger.error("❌ ABORTED: No authorization file (allowed_targets.yml) found")
            return
        
        logger.info("✓ Authorization verified")
        logger.info(f"📁 Output directory: {self.bundle_dir}\n")
        
        self.forensics_data["system_info"] = self.collect_system_info()
        self.forensics_data["processes"] = self.collect_process_list()
        self.forensics_data["network_connections"] = self.collect_network_connections()
        self.forensics_data["open_files"] = self.collect_open_files()
        self.forensics_data["logs"] = self.collect_recent_logs()
        self.forensics_data["environment"] = self.collect_environment_variables()
        
        summary_file = self.bundle_dir / "forensics_summary.json"
        with summary_file.open("w") as f:
            summary = {
                "incident_id": f"incident_{self.timestamp}",
                "collection_date": datetime.now().isoformat(),
                "system_info": self.forensics_data["system_info"],
                "statistics": {
                    "processes_collected": len(self.forensics_data["processes"]),
                    "network_connections": len(self.forensics_data["network_connections"]),
                    "open_files": len(self.forensics_data["open_files"]),
                    "log_files": len(self.forensics_data["logs"]),
                    "environment_variables": len(self.forensics_data["environment"])
                }
            }
            json.dump(summary, f, indent=2)
        
        self.calculate_checksum(summary_file)
        
        self.create_manifest()
        self.create_chain_of_custody()
        
        bundle_path = self.create_bundle()
        
        logger.info("\n" + "=" * 60)
        logger.info("📊 COLLECTION SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Incident ID: incident_{self.timestamp}")
        logger.info(f"Files Collected: {len(self.file_checksums)}")
        logger.info(f"Bundle Size: {bundle_path.stat().st_size / 1024:.2f} KB")
        logger.info(f"\n✅ Triage collection complete!")
        logger.info(f"📦 Bundle: {bundle_path.absolute()}")
        logger.info(f"📁 Evidence: {self.bundle_dir.absolute()}")


def main():
    parser = argparse.ArgumentParser(description="Incident Triage Helper")
    parser.add_argument("--collect", action="store_true", help="Collect forensics data")
    parser.add_argument("--output-dir", default="forensics", help="Output directory")
    parser.add_argument('--authorized', action='store_true',
                       help='Confirm you have authorization to perform this action')
    args = parser.parse_args()
    
    if args.collect:
        helper = IncidentTriageHelper(args.output_dir)
        helper.collect_all()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
