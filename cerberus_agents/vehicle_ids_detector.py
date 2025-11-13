#!/usr/bin/env python3
"""
Module 12: Vehicle IDS/Detection Modules
Intrusion detection for vehicle networks
"""

import logging
import time
from typing import Optional, Dict, List, Any
from collections import defaultdict
import statistics

from .automotive_core import (
    CANInterface,
    InterfaceMode,
    OperationMode,
    OperationRisk,
    get_safety_manager
)


logger = logging.getLogger(__name__)


class VehicleIDSDetector:
    """
    Vehicle Intrusion Detection System
    Anomaly detection for CAN bus and vehicle networks
    """
    
    def __init__(self, mode: InterfaceMode = InterfaceMode.SIMULATOR):
        self.mode = mode
        self.safety = get_safety_manager()
        self.baseline_profile: Dict[int, Dict[str, Any]] = {}
        self.alerts: List[Dict[str, Any]] = []
    
    def run(
        self,
        target: str = "vehicle",
        duration: int = 60,
        detection_mode: str = "anomaly",
        enable_rules: bool = True
    ) -> Dict[str, Any]:
        """
        Run IDS detection
        
        Args:
            target: Target vehicle identifier
            duration: Monitoring duration in seconds
            detection_mode: Detection mode (anomaly, signature, hybrid)
            enable_rules: Enable rule-based detection
            
        Returns:
            Detection results
        """
        logger.info(f"🛡️ Starting Vehicle IDS Detector")
        logger.info(f"Target: {target}, Mode: {detection_mode}, Duration: {duration}s")
        
        # Check authorization
        if not self.safety.check_authorization(
            operation="ids_detection",
            mode=OperationMode.SIMULATOR if self.mode == InterfaceMode.SIMULATOR else OperationMode.HARDWARE_READ_ONLY,
            risk_level=OperationRisk.SAFE,
            target=target
        ):
            logger.error("❌ Operation not authorized")
            return {"error": "Authorization required"}
        
        results = {
            "target": target,
            "duration": duration,
            "detection_mode": detection_mode,
            "mode": self.mode.value,
            "messages_analyzed": 0,
            "alerts": [],
            "statistics": {}
        }
        
        # Phase 1: Learn baseline (first 1/3 of duration)
        baseline_duration = duration // 3
        logger.info(f"📊 Phase 1: Learning baseline ({baseline_duration}s)...")
        self._learn_baseline(baseline_duration)
        
        # Phase 2: Active detection (remaining duration)
        detection_duration = duration - baseline_duration
        logger.info(f"🔍 Phase 2: Active detection ({detection_duration}s)...")
        
        can_interface = CANInterface(mode=self.mode)
        if not can_interface.connect():
            return {"error": "Failed to connect to CAN interface"}
        
        try:
            start_time = time.time()
            message_stats = defaultdict(list)
            
            while time.time() - start_time < detection_duration:
                msg = can_interface.receive(timeout=0.1)
                
                if msg:
                    results["messages_analyzed"] += 1
                    
                    # Record message timing
                    message_stats[msg.arbitration_id].append(time.time())
                    
                    # Anomaly detection
                    if detection_mode in ["anomaly", "hybrid"]:
                        anomaly_alerts = self._detect_anomalies(msg, message_stats)
                        self.alerts.extend(anomaly_alerts)
                    
                    # Rule-based detection
                    if enable_rules and detection_mode in ["signature", "hybrid"]:
                        rule_alerts = self._apply_rules(msg)
                        self.alerts.extend(rule_alerts)
            
            results["alerts"] = self.alerts
            results["statistics"] = self._calculate_statistics(message_stats)
            
            # Log operation
            self.safety.log_operation(
                operation="ids_detection",
                mode=OperationMode.SIMULATOR if self.mode == InterfaceMode.SIMULATOR else OperationMode.HARDWARE_READ_ONLY,
                risk_level=OperationRisk.SAFE,
                details={"target": target, "alerts": len(self.alerts)},
                success=True
            )
            
        finally:
            can_interface.disconnect()
        
        # Generate report
        self._generate_report(results)
        
        return results
    
    def _learn_baseline(self, duration: int):
        """Learn normal traffic baseline"""
        can_interface = CANInterface(mode=self.mode)
        if not can_interface.connect():
            logger.error("Failed to connect for baseline learning")
            return
        
        try:
            start_time = time.time()
            message_data = defaultdict(lambda: {
                'count': 0,
                'intervals': [],
                'data_samples': []
            })
            
            last_msg_time = defaultdict(float)
            
            while time.time() - start_time < duration:
                msg = can_interface.receive(timeout=0.1)
                
                if msg:
                    msg_id = msg.arbitration_id
                    current_time = time.time()
                    
                    message_data[msg_id]['count'] += 1
                    message_data[msg_id]['data_samples'].append(msg.data)
                    
                    # Calculate interval
                    if last_msg_time[msg_id] > 0:
                        interval = current_time - last_msg_time[msg_id]
                        message_data[msg_id]['intervals'].append(interval)
                    
                    last_msg_time[msg_id] = current_time
            
            # Calculate baseline statistics
            for msg_id, data in message_data.items():
                if data['intervals']:
                    self.baseline_profile[msg_id] = {
                        'avg_interval': statistics.mean(data['intervals']),
                        'std_interval': statistics.stdev(data['intervals']) if len(data['intervals']) > 1 else 0,
                        'count': data['count'],
                        'data_length': len(data['data_samples'][0]) if data['data_samples'] else 0
                    }
            
            logger.info(f"  ✅ Learned baseline for {len(self.baseline_profile)} message IDs")
            
        finally:
            can_interface.disconnect()
    
    def _detect_anomalies(
        self,
        msg: Any,
        message_stats: Dict[int, List[float]]
    ) -> List[Dict[str, Any]]:
        """Detect anomalous patterns"""
        alerts = []
        msg_id = msg.arbitration_id
        
        # Check if this is a new/unknown message ID
        if msg_id not in self.baseline_profile:
            alerts.append({
                "severity": "MEDIUM",
                "type": "Unknown Message ID",
                "message_id": f"0x{msg_id:03X}",
                "description": f"Message ID 0x{msg_id:03X} not seen during baseline",
                "timestamp": time.time()
            })
            return alerts
        
        baseline = self.baseline_profile[msg_id]
        
        # Check message frequency anomaly
        if len(message_stats[msg_id]) > 1:
            recent_intervals = [
                message_stats[msg_id][i+1] - message_stats[msg_id][i]
                for i in range(max(0, len(message_stats[msg_id]) - 10), len(message_stats[msg_id]) - 1)
            ]
            
            if recent_intervals:
                avg_recent = statistics.mean(recent_intervals)
                expected = baseline['avg_interval']
                threshold = baseline['std_interval'] * 3  # 3 sigma
                
                if abs(avg_recent - expected) > threshold and threshold > 0:
                    alerts.append({
                        "severity": "HIGH",
                        "type": "Frequency Anomaly",
                        "message_id": f"0x{msg_id:03X}",
                        "description": f"Unusual message frequency for 0x{msg_id:03X}",
                        "expected_interval": round(expected, 4),
                        "observed_interval": round(avg_recent, 4),
                        "timestamp": time.time()
                    })
        
        # Check data length anomaly
        if len(msg.data) != baseline['data_length']:
            alerts.append({
                "severity": "HIGH",
                "type": "Data Length Anomaly",
                "message_id": f"0x{msg_id:03X}",
                "description": f"Unexpected data length for 0x{msg_id:03X}",
                "expected_length": baseline['data_length'],
                "observed_length": len(msg.data),
                "timestamp": time.time()
            })
        
        return alerts
    
    def _apply_rules(self, msg: Any) -> List[Dict[str, Any]]:
        """Apply rule-based detection"""
        alerts = []
        msg_id = msg.arbitration_id
        
        # Rule 1: High-severity diagnostic commands
        if msg_id in [0x7E0, 0x7E1] and len(msg.data) > 0:
            sid = msg.data[0]
            
            # ECU Reset command
            if sid == 0x11:
                alerts.append({
                    "severity": "CRITICAL",
                    "type": "ECU Reset Command",
                    "message_id": f"0x{msg_id:03X}",
                    "description": "ECU Reset command detected",
                    "timestamp": time.time()
                })
            
            # Security Access
            elif sid == 0x27:
                alerts.append({
                    "severity": "HIGH",
                    "type": "Security Access Attempt",
                    "message_id": f"0x{msg_id:03X}",
                    "description": "Security access attempt detected",
                    "timestamp": time.time()
                })
        
        # Rule 2: Unusual engine RPM values
        if msg_id == 0x110 and len(msg.data) >= 2:
            rpm = int.from_bytes(msg.data[:2], 'big')
            if rpm > 7000:  # Redline exceeded
                alerts.append({
                    "severity": "CRITICAL",
                    "type": "Engine RPM Anomaly",
                    "message_id": f"0x{msg_id:03X}",
                    "description": f"Excessive RPM detected: {rpm}",
                    "timestamp": time.time()
                })
        
        # Rule 3: Replay attack detection (duplicate messages in short time)
        # (This would require maintaining a short-term message cache)
        
        return alerts
    
    def _calculate_statistics(self, message_stats: Dict[int, List[float]]) -> Dict[str, Any]:
        """Calculate detection statistics"""
        total_messages = sum(len(times) for times in message_stats.values())
        unique_ids = len(message_stats)
        
        # Categorize alerts by severity
        severity_counts = defaultdict(int)
        for alert in self.alerts:
            severity_counts[alert['severity']] += 1
        
        # Categorize alerts by type
        type_counts = defaultdict(int)
        for alert in self.alerts:
            type_counts[alert['type']] += 1
        
        return {
            "total_messages": total_messages,
            "unique_message_ids": unique_ids,
            "total_alerts": len(self.alerts),
            "alerts_by_severity": dict(severity_counts),
            "alerts_by_type": dict(type_counts),
            "baseline_ids": len(self.baseline_profile)
        }
    
    def _generate_report(self, results: Dict[str, Any]):
        """Generate IDS report"""
        logger.info("\n" + "=" * 70)
        logger.info("🛡️ VEHICLE IDS DETECTION REPORT")
        logger.info("=" * 70)
        logger.info(f"Target: {results['target']}")
        logger.info(f"Detection Mode: {results['detection_mode']}")
        logger.info(f"Duration: {results['duration']}s")
        logger.info(f"Messages Analyzed: {results['messages_analyzed']}")
        logger.info("=" * 70)
        
        stats = results.get("statistics", {})
        
        logger.info(f"\n📊 Statistics:")
        logger.info(f"  Baseline Message IDs: {stats.get('baseline_ids', 0)}")
        logger.info(f"  Unique Message IDs: {stats.get('unique_message_ids', 0)}")
        logger.info(f"  Total Alerts: {stats.get('total_alerts', 0)}")
        
        # Alerts by severity
        severity_counts = stats.get("alerts_by_severity", {})
        if severity_counts:
            logger.info(f"\n  Alerts by Severity:")
            for severity, count in sorted(severity_counts.items()):
                logger.info(f"    {severity}: {count}")
        
        # Alert details
        if results.get("alerts"):
            logger.info(f"\n🚨 ALERTS DETECTED: {len(results['alerts'])}")
            
            # Show top 10 alerts
            for alert in results["alerts"][:10]:
                logger.info(f"\n  [{alert['severity']}] {alert['type']}")
                logger.info(f"    Message ID: {alert.get('message_id', 'N/A')}")
                logger.info(f"    Description: {alert['description']}")


def run_vehicle_ids_detector(
    target: str = "vehicle",
    duration: int = 60,
    detection_mode: str = "hybrid"
) -> Dict[str, Any]:
    """
    Main entry point for vehicle IDS
    """
    detector = VehicleIDSDetector()
    return detector.run(
        target=target,
        duration=duration,
        detection_mode=detection_mode
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    results = run_vehicle_ids_detector(duration=30, detection_mode="hybrid")
    print(f"\nDetection complete. Generated {len(results['alerts'])} alerts.")
