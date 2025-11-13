#!/usr/bin/env python3
"""
Module 7: Hardware-in-the-Loop & Emulator Integration
Vehicle simulator integration and test scenarios
"""

import logging
import time
from typing import Optional, Dict, List, Any

from .automotive_core import (
    CANInterface,
    CANMessage,
    InterfaceMode,
    OperationMode,
    OperationRisk,
    get_safety_manager
)


logger = logging.getLogger(__name__)


class HILEmulatorIntegration:
    """
    Hardware-in-the-Loop (HIL) Emulator Integration
    Run test scenarios in vehicle simulators
    """
    
    def __init__(self, mode: InterfaceMode = InterfaceMode.SIMULATOR):
        self.mode = mode
        self.safety = get_safety_manager()
        self.can_interface: Optional[CANInterface] = None
    
    def run(
        self,
        scenario: str = "engine_start",
        target: str = "vehicle_simulator",
        duration: int = 30
    ) -> Dict[str, Any]:
        """
        Run HIL test scenario
        
        Args:
            scenario: Test scenario name
            target: Target vehicle/simulator
            duration: Scenario duration in seconds
            
        Returns:
            Test results
        """
        logger.info(f"🎮 Starting HIL Emulator Integration")
        logger.info(f"Scenario: {scenario}, Target: {target}")
        
        # Check authorization
        if not self.safety.check_authorization(
            operation="hil_scenario",
            mode=OperationMode.SIMULATOR,
            risk_level=OperationRisk.SAFE,
            target=target
        ):
            logger.error("❌ Operation not authorized")
            return {"error": "Authorization required"}
        
        results = {
            "scenario": scenario,
            "target": target,
            "duration": duration,
            "mode": self.mode.value,
            "scenario_results": {},
            "messages_sent": 0,
            "messages_received": 0
        }
        
        # Setup CAN interface
        self.can_interface = CANInterface(mode=self.mode)
        if not self.can_interface.connect():
            return {"error": "Failed to connect to simulator"}
        
        try:
            # Run scenario
            if scenario == "engine_start":
                results["scenario_results"] = self._run_engine_start_scenario(duration)
            elif scenario == "adas_sensor":
                results["scenario_results"] = self._run_adas_sensor_scenario(duration)
            elif scenario == "ignition_cycle":
                results["scenario_results"] = self._run_ignition_cycle_scenario(duration)
            else:
                results["scenario_results"] = {"error": f"Unknown scenario: {scenario}"}
            
            results["messages_sent"] = self.can_interface.simulator_messages.__len__() if hasattr(self.can_interface, 'simulator_messages') else 0
            
            # Log operation
            self.safety.log_operation(
                operation="hil_scenario",
                mode=OperationMode.SIMULATOR,
                risk_level=OperationRisk.SAFE,
                details={"scenario": scenario, "target": target},
                success=True
            )
            
        finally:
            self.can_interface.disconnect()
        
        # Generate report
        self._generate_report(results)
        
        return results
    
    def _run_engine_start_scenario(self, duration: int) -> Dict[str, Any]:
        """Simulate engine start sequence"""
        logger.info("  Running engine start scenario...")
        
        results = {
            "phases": [],
            "total_messages": 0,
            "success": True
        }
        
        # Phase 1: Ignition ON
        logger.info("    Phase 1: Ignition ON")
        self._send_message(0x100, bytes([0x01]))  # Ignition status
        time.sleep(0.5)
        results["phases"].append("Ignition ON")
        results["total_messages"] += 1
        
        # Phase 2: Engine cranking
        logger.info("    Phase 2: Engine cranking")
        for i in range(5):
            rpm = i * 100
            self._send_message(0x110, rpm.to_bytes(2, 'big'))  # RPM rising
            time.sleep(0.1)
            results["total_messages"] += 1
        results["phases"].append("Cranking")
        
        # Phase 3: Engine running
        logger.info("    Phase 3: Engine running")
        for i in range(int(duration - 3)):
            rpm = 800 + (i % 100)  # Idle RPM ~800
            self._send_message(0x110, rpm.to_bytes(2, 'big'))
            time.sleep(0.1)
            results["total_messages"] += 1
        results["phases"].append("Running")
        
        logger.info("  ✅ Engine start scenario complete")
        return results
    
    def _run_adas_sensor_scenario(self, duration: int) -> Dict[str, Any]:
        """Simulate ADAS sensor messages"""
        logger.info("  Running ADAS sensor scenario...")
        
        results = {
            "sensors_simulated": [],
            "total_messages": 0,
            "success": True
        }
        
        start_time = time.time()
        
        while time.time() - start_time < duration:
            # Radar sensor
            self._send_message(0x300, bytes([0x01, 0x02, 0x03, 0x04]))
            results["total_messages"] += 1
            
            # Camera sensor
            self._send_message(0x310, bytes([0x05, 0x06, 0x07, 0x08]))
            results["total_messages"] += 1
            
            # Lidar sensor
            self._send_message(0x320, bytes([0x09, 0x0A, 0x0B, 0x0C]))
            results["total_messages"] += 1
            
            time.sleep(0.1)
        
        results["sensors_simulated"] = ["Radar", "Camera", "Lidar"]
        
        logger.info("  ✅ ADAS sensor scenario complete")
        return results
    
    def _run_ignition_cycle_scenario(self, duration: int) -> Dict[str, Any]:
        """Simulate complete ignition cycle"""
        logger.info("  Running ignition cycle scenario...")
        
        results = {
            "cycles_completed": 0,
            "total_messages": 0,
            "success": True
        }
        
        cycle_duration = max(5, duration // 3)
        
        for cycle in range(max(1, duration // cycle_duration)):
            logger.info(f"    Cycle {cycle + 1}: OFF -> ACC -> ON -> OFF")
            
            # OFF
            self._send_message(0x100, bytes([0x00]))
            time.sleep(1)
            results["total_messages"] += 1
            
            # ACC (Accessory)
            self._send_message(0x100, bytes([0x01]))
            time.sleep(1)
            results["total_messages"] += 1
            
            # ON (Run)
            self._send_message(0x100, bytes([0x02]))
            time.sleep(cycle_duration - 3)
            results["total_messages"] += 1
            
            # OFF
            self._send_message(0x100, bytes([0x00]))
            time.sleep(1)
            results["total_messages"] += 1
            
            results["cycles_completed"] += 1
        
        logger.info("  ✅ Ignition cycle scenario complete")
        return results
    
    def _send_message(self, msg_id: int, data: bytes):
        """Send CAN message"""
        if self.can_interface:
            msg = CANMessage(arbitration_id=msg_id, data=data)
            self.can_interface.send(msg)
    
    def _generate_report(self, results: Dict[str, Any]):
        """Generate test report"""
        logger.info("\n" + "=" * 70)
        logger.info("🎮 HIL EMULATOR INTEGRATION REPORT")
        logger.info("=" * 70)
        logger.info(f"Scenario: {results['scenario']}")
        logger.info(f"Target: {results['target']}")
        logger.info(f"Duration: {results['duration']}s")
        logger.info(f"Mode: {results['mode']}")
        logger.info("=" * 70)
        
        scenario_results = results.get("scenario_results", {})
        
        if "phases" in scenario_results:
            logger.info(f"\nPhases Completed: {len(scenario_results['phases'])}")
            for phase in scenario_results["phases"]:
                logger.info(f"  ✅ {phase}")
        
        if "sensors_simulated" in scenario_results:
            logger.info(f"\nSensors Simulated: {', '.join(scenario_results['sensors_simulated'])}")
        
        if "cycles_completed" in scenario_results:
            logger.info(f"\nIgnition Cycles: {scenario_results['cycles_completed']}")
        
        if "total_messages" in scenario_results:
            logger.info(f"\nTotal Messages: {scenario_results['total_messages']}")


def run_hil_emulator(
    scenario: str = "engine_start",
    target: str = "vehicle_simulator",
    duration: int = 30
) -> Dict[str, Any]:
    """
    Main entry point for HIL emulator integration
    """
    hil = HILEmulatorIntegration()
    return hil.run(scenario=scenario, target=target, duration=duration)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    results = run_hil_emulator(scenario="engine_start", duration=10)
    print(f"\nScenario complete. Total messages: {results['scenario_results'].get('total_messages', 0)}")
