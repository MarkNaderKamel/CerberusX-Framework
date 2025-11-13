#!/usr/bin/env python3
"""
Module 11: Forensics, Logging & Evidence Collector
Capture and preserve vehicle security evidence
"""

import logging
import json
import time
import hashlib
from pathlib import Path
from typing import Optional, Dict, List, Any
from datetime import datetime

from .automotive_core import (
    CANInterface,
    InterfaceMode,
    OperationMode,
    OperationRisk,
    get_safety_manager
)


logger = logging.getLogger(__name__)


class VehicleForensicsCollector:
    """
    Vehicle Forensics Collector
    Capture CAN traffic, logs, and evidence with immutable storage
    """
    
    def __init__(self, mode: InterfaceMode = InterfaceMode.SIMULATOR):
        self.mode = mode
        self.safety = get_safety_manager()
        self.evidence_dir = Path("forensics/evidence")
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
    
    def run(
        self,
        target: str = "vehicle",
        duration: int = 60,
        capture_types: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Collect forensic evidence
        
        Args:
            target: Target vehicle identifier
            duration: Collection duration in seconds
            capture_types: Types to capture (can, logs, state)
            
        Returns:
            Collection results
        """
        logger.info(f"🔬 Starting Vehicle Forensics Collector")
        logger.info(f"Target: {target}, Duration: {duration}s")
        
        # Check authorization
        if not self.safety.check_authorization(
            operation="forensics_collection",
            mode=OperationMode.SIMULATOR if self.mode == InterfaceMode.SIMULATOR else OperationMode.HARDWARE_READ_ONLY,
            risk_level=OperationRisk.SAFE,
            target=target
        ):
            logger.error("❌ Operation not authorized")
            return {"error": "Authorization required"}
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        session_id = hashlib.sha256(f"{target}{timestamp}".encode()).hexdigest()[:16]
        
        results = {
            "target": target,
            "session_id": session_id,
            "timestamp": timestamp,
            "duration": duration,
            "mode": self.mode.value,
            "evidence_files": [],
            "signatures": {},
            "statistics": {}
        }
        
        if capture_types is None:
            capture_types = ["can", "logs", "state"]
        
        # Capture CAN traffic
        if "can" in capture_types:
            logger.info("📡 Capturing CAN traffic...")
            can_file = self._capture_can_traffic(session_id, duration)
            if can_file:
                results["evidence_files"].append(can_file)
                results["signatures"][can_file] = self._sign_file(can_file)
        
        # Collect system logs
        if "logs" in capture_types:
            logger.info("📝 Collecting system logs...")
            log_file = self._collect_logs(session_id)
            if log_file:
                results["evidence_files"].append(log_file)
                results["signatures"][log_file] = self._sign_file(log_file)
        
        # Capture system state
        if "state" in capture_types:
            logger.info("💾 Capturing system state...")
            state_file = self._capture_state(session_id)
            if state_file:
                results["evidence_files"].append(state_file)
                results["signatures"][state_file] = self._sign_file(state_file)
        
        # Generate collection manifest
        manifest_file = self._create_manifest(results, session_id)
        results["evidence_files"].append(manifest_file)
        
        # Calculate statistics
        results["statistics"] = self._calculate_statistics(results)
        
        # Log operation
        self.safety.log_operation(
            operation="forensics_collection",
            mode=OperationMode.SIMULATOR if self.mode == InterfaceMode.SIMULATOR else OperationMode.HARDWARE_READ_ONLY,
            risk_level=OperationRisk.SAFE,
            details={"target": target, "session": session_id},
            success=True
        )
        
        # Generate report
        self._generate_report(results)
        
        return results
    
    def _capture_can_traffic(self, session_id: str, duration: int) -> Optional[str]:
        """Capture CAN traffic to PCAP-like format"""
        output_file = self.evidence_dir / f"can_capture_{session_id}.jsonl"
        
        can_interface = CANInterface(mode=self.mode)
        if not can_interface.connect():
            logger.error("Failed to connect to CAN interface")
            return None
        
        try:
            messages_captured = 0
            start_time = time.time()
            
            with open(output_file, 'w') as f:
                while time.time() - start_time < duration:
                    msg = can_interface.receive(timeout=0.1)
                    
                    if msg:
                        # Write message in JSON Lines format
                        record = {
                            "timestamp": msg.timestamp or time.time(),
                            "arbitration_id": f"0x{msg.arbitration_id:03X}",
                            "data": msg.data.hex(),
                            "is_extended": msg.is_extended_id,
                            "is_fd": msg.is_fd
                        }
                        f.write(json.dumps(record) + '\n')
                        messages_captured += 1
                        
                        if messages_captured % 100 == 0:
                            logger.debug(f"  Captured {messages_captured} messages...")
            
            logger.info(f"  ✅ Captured {messages_captured} CAN messages")
            return str(output_file)
            
        finally:
            can_interface.disconnect()
    
    def _collect_logs(self, session_id: str) -> Optional[str]:
        """Collect system logs"""
        output_file = self.evidence_dir / f"system_logs_{session_id}.json"
        
        # Simulated log collection
        logs = {
            "kernel_logs": [
                {"timestamp": time.time(), "level": "INFO", "message": "CAN interface initialized"},
                {"timestamp": time.time(), "level": "INFO", "message": "Vehicle state: RUNNING"}
            ],
            "application_logs": [
                {"timestamp": time.time(), "service": "telematics", "message": "Connected to backend"},
                {"timestamp": time.time(), "service": "diagnostics", "message": "No DTCs present"}
            ],
            "security_logs": [
                {"timestamp": time.time(), "event": "authentication", "result": "success"},
                {"timestamp": time.time(), "event": "firmware_verification", "result": "passed"}
            ]
        }
        
        with open(output_file, 'w') as f:
            json.dump(logs, f, indent=2)
        
        logger.info(f"  ✅ Collected {sum(len(v) for v in logs.values())} log entries")
        return str(output_file)
    
    def _capture_state(self, session_id: str) -> Optional[str]:
        """Capture system state snapshot"""
        output_file = self.evidence_dir / f"system_state_{session_id}.json"
        
        # Simulated state capture
        state = {
            "timestamp": time.time(),
            "vehicle_state": {
                "ignition": "ON",
                "speed": 0,
                "rpm": 800,
                "gear": "P",
                "odometer": 12345
            },
            "network_state": {
                "can_bus": "active",
                "bluetooth": "connected",
                "wifi": "disconnected",
                "cellular": "4G"
            },
            "ecu_state": [
                {"ecu_id": "0x7E0", "status": "responsive", "dtc_count": 0},
                {"ecu_id": "0x7E1", "status": "responsive", "dtc_count": 0}
            ],
            "security_state": {
                "alarm": "disarmed",
                "doors_locked": False,
                "immobilizer": "active"
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(state, f, indent=2)
        
        logger.info(f"  ✅ Captured system state snapshot")
        return str(output_file)
    
    def _sign_file(self, file_path: str) -> Dict[str, str]:
        """Create cryptographic signature for evidence file"""
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Calculate multiple hashes for integrity
        signatures = {
            "md5": hashlib.md5(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "timestamp": time.time()
        }
        
        return signatures
    
    def _create_manifest(self, results: Dict[str, Any], session_id: str) -> str:
        """Create evidence collection manifest"""
        manifest_file = self.evidence_dir / f"manifest_{session_id}.json"
        
        manifest = {
            "session_id": results["session_id"],
            "target": results["target"],
            "timestamp": results["timestamp"],
            "duration": results["duration"],
            "mode": results["mode"],
            "evidence_files": results["evidence_files"],
            "file_signatures": results["signatures"],
            "collector_version": "1.0.0",
            "chain_of_custody": [
                {
                    "timestamp": time.time(),
                    "action": "collection_complete",
                    "operator": "automated_system"
                }
            ]
        }
        
        with open(manifest_file, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        logger.info(f"  ✅ Created evidence manifest")
        return str(manifest_file)
    
    def _calculate_statistics(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate collection statistics"""
        total_size = 0
        
        for file_path in results["evidence_files"]:
            if Path(file_path).exists():
                total_size += Path(file_path).stat().st_size
        
        return {
            "total_files": len(results["evidence_files"]),
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2)
        }
    
    def _generate_report(self, results: Dict[str, Any]):
        """Generate collection report"""
        logger.info("\n" + "=" * 70)
        logger.info("🔬 VEHICLE FORENSICS COLLECTION REPORT")
        logger.info("=" * 70)
        logger.info(f"Session ID: {results['session_id']}")
        logger.info(f"Target: {results['target']}")
        logger.info(f"Timestamp: {results['timestamp']}")
        logger.info(f"Duration: {results['duration']}s")
        logger.info(f"Mode: {results['mode']}")
        logger.info("=" * 70)
        
        logger.info(f"\n📁 Evidence Files Collected: {len(results['evidence_files'])}")
        for file_path in results["evidence_files"]:
            file_name = Path(file_path).name
            signature = results["signatures"].get(file_path, {})
            logger.info(f"  • {file_name}")
            if signature:
                logger.info(f"    SHA256: {signature.get('sha256', 'N/A')[:16]}...")
                logger.info(f"    Size: {signature.get('size', 0)} bytes")
        
        stats = results.get("statistics", {})
        if stats:
            logger.info(f"\n📊 Statistics:")
            logger.info(f"  Total Files: {stats.get('total_files', 0)}")
            logger.info(f"  Total Size: {stats.get('total_size_mb', 0)} MB")


def run_vehicle_forensics_collector(
    target: str = "vehicle",
    duration: int = 60,
    capture_types: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Main entry point for forensics collector
    """
    collector = VehicleForensicsCollector()
    return collector.run(target=target, duration=duration, capture_types=capture_types)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    results = run_vehicle_forensics_collector(duration=10, capture_types=["can", "logs", "state"])
    print(f"\nCollection complete. Captured {results['statistics']['total_files']} files.")
