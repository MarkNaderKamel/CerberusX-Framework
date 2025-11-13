#!/usr/bin/env python3
"""
Module 1: Vehicle Network Interface & Abstraction
Provides unified API for CAN, CAN-FD, LIN, FlexRay, and ISO-TP networks
"""

import logging
import time
from typing import Optional, Dict, List, Any
from collections import defaultdict

from .automotive_core import (
    CANInterface,
    LINInterface,
    FlexRayInterface,
    InterfaceMode,
    OperationMode,
    OperationRisk,
    get_safety_manager
)


logger = logging.getLogger(__name__)


class VehicleNetworkScanner:
    """
    Vehicle Network Scanner
    Passive monitoring and analysis of vehicle bus traffic
    """
    
    def __init__(self, mode: InterfaceMode = InterfaceMode.SIMULATOR):
        self.mode = mode
        self.safety = get_safety_manager()
        self.can_interface: Optional[CANInterface] = None
        self.lin_interface: Optional[LINInterface] = None
        self.flexray_interface: Optional[FlexRayInterface] = None
        self.message_stats: Dict[str, Dict] = defaultdict(lambda: {
            'count': 0,
            'first_seen': None,
            'last_seen': None,
            'data_samples': []
        })
    
    def run(
        self,
        target: str = "vehicle_simulator",
        duration: int = 30,
        bus_types: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Run vehicle network scanner
        
        Args:
            target: Target vehicle identifier
            duration: Scan duration in seconds
            bus_types: List of bus types to scan (can, lin, flexray)
            
        Returns:
            Scan results
        """
        logger.info(f"🚗 Starting Vehicle Network Scanner")
        logger.info(f"Target: {target}, Duration: {duration}s, Mode: {self.mode.value}")
        
        # Check authorization
        if not self.safety.check_authorization(
            operation="vehicle_network_scan",
            mode=OperationMode.SIMULATOR if self.mode == InterfaceMode.SIMULATOR else OperationMode.HARDWARE_READ_ONLY,
            risk_level=OperationRisk.SAFE,
            target=target
        ):
            logger.error("❌ Operation not authorized")
            return {"error": "Authorization required"}
        
        results = {
            "target": target,
            "duration": duration,
            "mode": self.mode.value,
            "buses_scanned": [],
            "findings": {}
        }
        
        if bus_types is None:
            bus_types = ["can"]
        
        # Scan each bus type
        if "can" in bus_types:
            logger.info("🔍 Scanning CAN bus...")
            results["buses_scanned"].append("CAN")
            results["findings"]["can"] = self._scan_can_bus(duration)
        
        if "lin" in bus_types:
            logger.info("🔍 Scanning LIN bus...")
            results["buses_scanned"].append("LIN")
            results["findings"]["lin"] = self._scan_lin_bus(duration)
        
        if "flexray" in bus_types:
            logger.info("🔍 Scanning FlexRay bus...")
            results["buses_scanned"].append("FlexRay")
            results["findings"]["flexray"] = self._scan_flexray_bus(duration)
        
        # Log operation
        self.safety.log_operation(
            operation="vehicle_network_scan",
            mode=OperationMode.SIMULATOR if self.mode == InterfaceMode.SIMULATOR else OperationMode.HARDWARE_READ_ONLY,
            risk_level=OperationRisk.SAFE,
            details={"target": target, "buses": bus_types},
            success=True
        )
        
        # Generate report
        self._generate_report(results)
        
        return results
    
    def _scan_can_bus(self, duration: int) -> Dict[str, Any]:
        """Scan CAN bus for specified duration"""
        self.can_interface = CANInterface(mode=self.mode)
        
        if not self.can_interface.connect():
            return {"error": "Failed to connect to CAN interface"}
        
        findings = {
            "messages_captured": 0,
            "unique_ids": set(),
            "message_frequencies": {},
            "suspicious_patterns": []
        }
        
        start_time = time.time()
        message_times = defaultdict(list)
        
        try:
            while time.time() - start_time < duration:
                msg = self.can_interface.receive(timeout=0.1)
                
                if msg:
                    findings["messages_captured"] += 1
                    findings["unique_ids"].add(msg.arbitration_id)
                    
                    # Track message timing for frequency analysis
                    message_times[msg.arbitration_id].append(time.time())
                    
                    # Store message sample
                    msg_key = f"0x{msg.arbitration_id:03X}"
                    self.message_stats[msg_key]['count'] += 1
                    if self.message_stats[msg_key]['first_seen'] is None:
                        self.message_stats[msg_key]['first_seen'] = time.time()
                    self.message_stats[msg_key]['last_seen'] = time.time()
                    
                    # Store data samples (keep last 5)
                    if len(self.message_stats[msg_key]['data_samples']) < 5:
                        self.message_stats[msg_key]['data_samples'].append(msg.data)
        
        finally:
            self.can_interface.disconnect()
        
        # Calculate message frequencies
        for msg_id, times in message_times.items():
            if len(times) > 1:
                intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
                avg_interval = sum(intervals) / len(intervals)
                frequency = 1.0 / avg_interval if avg_interval > 0 else 0
                findings["message_frequencies"][f"0x{msg_id:03X}"] = {
                    "frequency_hz": round(frequency, 2),
                    "count": len(times)
                }
        
        # Detect suspicious patterns
        findings["suspicious_patterns"] = self._detect_suspicious_patterns(message_times)
        
        findings["unique_ids"] = len(findings["unique_ids"])
        
        logger.info(f"✅ CAN scan complete: {findings['messages_captured']} messages, "
                   f"{findings['unique_ids']} unique IDs")
        
        return findings
    
    def _scan_lin_bus(self, duration: int) -> Dict[str, Any]:
        """Scan LIN bus for specified duration"""
        self.lin_interface = LINInterface(mode=self.mode)
        
        if not self.lin_interface.connect():
            return {"error": "Failed to connect to LIN interface"}
        
        findings = {
            "messages_captured": 0,
            "unique_frame_ids": set()
        }
        
        start_time = time.time()
        
        try:
            while time.time() - start_time < duration:
                msg = self.lin_interface.receive(timeout=0.1)
                
                if msg:
                    findings["messages_captured"] += 1
                    findings["unique_frame_ids"].add(msg.frame_id)
        
        finally:
            self.lin_interface.disconnect()
        
        findings["unique_frame_ids"] = len(findings["unique_frame_ids"])
        
        logger.info(f"✅ LIN scan complete: {findings['messages_captured']} messages")
        
        return findings
    
    def _scan_flexray_bus(self, duration: int) -> Dict[str, Any]:
        """Scan FlexRay bus for specified duration"""
        self.flexray_interface = FlexRayInterface(mode=self.mode)
        
        if not self.flexray_interface.connect():
            return {"error": "Failed to connect to FlexRay interface"}
        
        findings = {
            "frames_captured": 0,
            "unique_slots": set()
        }
        
        start_time = time.time()
        
        try:
            while time.time() - start_time < duration:
                frame = self.flexray_interface.receive(timeout=0.1)
                
                if frame:
                    findings["frames_captured"] += 1
                    findings["unique_slots"].add(frame.slot_id)
        
        finally:
            self.flexray_interface.disconnect()
        
        findings["unique_slots"] = len(findings["unique_slots"])
        
        logger.info(f"✅ FlexRay scan complete: {findings['frames_captured']} frames")
        
        return findings
    
    def _detect_suspicious_patterns(self, message_times: Dict) -> List[str]:
        """Detect suspicious patterns in CAN traffic"""
        patterns = []
        
        # Check for abnormally high frequency messages (possible DoS)
        for msg_id, times in message_times.items():
            if len(times) > 100:
                intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
                avg_interval = sum(intervals) / len(intervals)
                if avg_interval < 0.001:  # Less than 1ms between messages
                    patterns.append(
                        f"High frequency detected for ID 0x{msg_id:03X} "
                        f"(~{1/avg_interval:.0f} Hz, possible DoS)"
                    )
        
        # Check for single-occurrence messages (possible injection)
        for msg_id, times in message_times.items():
            if len(times) == 1:
                patterns.append(
                    f"Single occurrence of ID 0x{msg_id:03X} (possible injection)"
                )
        
        return patterns
    
    def _generate_report(self, results: Dict[str, Any]):
        """Generate scan report"""
        logger.info("\n" + "=" * 70)
        logger.info("🚗 VEHICLE NETWORK SCAN REPORT")
        logger.info("=" * 70)
        logger.info(f"Target: {results['target']}")
        logger.info(f"Mode: {results['mode']}")
        logger.info(f"Duration: {results['duration']}s")
        logger.info(f"Buses Scanned: {', '.join(results['buses_scanned'])}")
        logger.info("=" * 70)
        
        for bus_type, findings in results['findings'].items():
            if 'error' not in findings:
                logger.info(f"\n📊 {bus_type.upper()} Bus Results:")
                
                if bus_type == "can":
                    logger.info(f"  Messages Captured: {findings['messages_captured']}")
                    logger.info(f"  Unique IDs: {findings['unique_ids']}")
                    
                    if findings['message_frequencies']:
                        logger.info("\n  Top Message Frequencies:")
                        sorted_freqs = sorted(
                            findings['message_frequencies'].items(),
                            key=lambda x: x[1]['frequency_hz'],
                            reverse=True
                        )
                        for msg_id, freq_data in sorted_freqs[:5]:
                            logger.info(f"    {msg_id}: {freq_data['frequency_hz']} Hz "
                                       f"({freq_data['count']} messages)")
                    
                    if findings['suspicious_patterns']:
                        logger.info("\n  ⚠️  Suspicious Patterns Detected:")
                        for pattern in findings['suspicious_patterns']:
                            logger.info(f"    • {pattern}")


def run_vehicle_network_scanner(
    target: str = "vehicle_simulator",
    duration: int = 30,
    mode: str = "simulator",
    bus_types: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Main entry point for vehicle network scanner
    
    Args:
        target: Target vehicle identifier
        duration: Scan duration in seconds
        mode: Operation mode (simulator/hardware)
        bus_types: List of bus types to scan
    
    Returns:
        Scan results
    """
    scanner = VehicleNetworkScanner(
        mode=InterfaceMode.SIMULATOR if mode == "simulator" else InterfaceMode.HARDWARE
    )
    
    return scanner.run(target=target, duration=duration, bus_types=bus_types)


if __name__ == "__main__":
    # Demo execution
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    
    results = run_vehicle_network_scanner(
        target="test_vehicle",
        duration=10,
        mode="simulator",
        bus_types=["can"]
    )
    
    print(f"\nScan complete. Captured {results['findings']['can']['messages_captured']} messages.")
