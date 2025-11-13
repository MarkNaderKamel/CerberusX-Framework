#!/usr/bin/env python3
"""
Module 8: Message Injection & Controlled Exploit Runner
Sandboxed message injection with safety controls
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
    get_safety_manager,
    AuthorizationToken
)


logger = logging.getLogger(__name__)


class MessageInjectionRunner:
    """
    Message Injection Runner
    Controlled CAN message injection with safety controls
    """
    
    def __init__(self, mode: InterfaceMode = InterfaceMode.SIMULATOR):
        self.mode = mode
        self.safety = get_safety_manager()
        self.can_interface: Optional[CANInterface] = None
    
    def run(
        self,
        target: str = "ecu_simulator",
        injection_plan: Optional[List[Dict[str, Any]]] = None,
        authorization_token: Optional[AuthorizationToken] = None,
        sandbox_mode: bool = True
    ) -> Dict[str, Any]:
        """
        Run message injection
        
        Args:
            target: Target ECU/vehicle
            injection_plan: List of messages to inject
            authorization_token: Hardware authorization token
            sandbox_mode: Run in sandbox (default: True)
            
        Returns:
            Injection results
        """
        logger.info(f"💉 Starting Message Injection Runner")
        logger.info(f"Target: {target}, Sandbox: {sandbox_mode}")
        
        # Determine operation mode
        if sandbox_mode or self.mode == InterfaceMode.SIMULATOR:
            operation_mode = OperationMode.SIMULATOR
            risk_level = OperationRisk.HIGH
        else:
            operation_mode = OperationMode.HARDWARE_FULL
            risk_level = OperationRisk.CRITICAL
        
        # Check authorization
        if not self.safety.check_authorization(
            operation="message_injection",
            mode=operation_mode,
            risk_level=risk_level,
            authorization_token=authorization_token,
            target=target
        ):
            logger.error("❌ Operation not authorized")
            return {"error": "Authorization required"}
        
        # Create rollback checkpoint for safety
        if not sandbox_mode:
            checkpoint_id = self.safety.create_rollback_checkpoint(
                operation="message_injection",
                state={"target": target, "timestamp": time.time()}
            )
            logger.info(f"✅ Rollback checkpoint created: {checkpoint_id}")
        
        results = {
            "target": target,
            "sandbox_mode": sandbox_mode,
            "mode": self.mode.value,
            "messages_injected": 0,
            "responses_received": 0,
            "injection_log": []
        }
        
        # Setup CAN interface
        self.can_interface = CANInterface(mode=self.mode)
        if not self.can_interface.connect():
            return {"error": "Failed to connect to CAN interface"}
        
        try:
            # Default injection plan if none provided
            if injection_plan is None:
                injection_plan = self._create_default_injection_plan()
            
            # Execute injection plan
            for idx, injection in enumerate(injection_plan):
                logger.info(f"  Injecting message {idx + 1}/{len(injection_plan)}...")
                
                # Rate limiting check
                if not self.safety.check_rate_limit("can_message_injection"):
                    logger.warning("  ⚠️  Rate limit reached, pausing...")
                    time.sleep(1.0)
                    continue
                
                # Inject message
                result = self._inject_message(injection)
                results["injection_log"].append(result)
                
                if result["success"]:
                    results["messages_injected"] += 1
                
                # Small delay between injections
                time.sleep(injection.get("delay", 0.1))
            
            # Log operation
            self.safety.log_operation(
                operation="message_injection",
                mode=operation_mode,
                risk_level=risk_level,
                details={"target": target, "messages": len(injection_plan)},
                success=True
            )
            
        finally:
            self.can_interface.disconnect()
        
        # Generate report
        self._generate_report(results)
        
        return results
    
    def _create_default_injection_plan(self) -> List[Dict[str, Any]]:
        """Create default injection plan for testing"""
        return [
            {
                "name": "Test TesterPresent",
                "arbitration_id": 0x7E0,
                "data": bytes([0x3E, 0x00]),
                "delay": 0.1
            },
            {
                "name": "Read VIN",
                "arbitration_id": 0x7E0,
                "data": bytes([0x09, 0x02]),
                "delay": 0.5
            },
            {
                "name": "Read DTCs",
                "arbitration_id": 0x7E0,
                "data": bytes([0x19, 0x02, 0xFF]),
                "delay": 0.5
            }
        ]
    
    def _inject_message(self, injection: Dict[str, Any]) -> Dict[str, Any]:
        """Inject single message"""
        result = {
            "name": injection.get("name", "Unknown"),
            "arbitration_id": injection["arbitration_id"],
            "success": False,
            "response": None,
            "timestamp": time.time()
        }
        
        try:
            # Create and send message
            msg = CANMessage(
                arbitration_id=injection["arbitration_id"],
                data=injection["data"]
            )
            
            if self.can_interface.send(msg):
                result["success"] = True
                logger.debug(f"    ✅ Injected: {injection.get('name', 'Message')}")
                
                # Try to receive response
                response = self.can_interface.receive(timeout=0.5)
                if response:
                    result["response"] = {
                        "id": f"0x{response.arbitration_id:03X}",
                        "data": response.data.hex()
                    }
            else:
                logger.warning(f"    ❌ Failed to inject: {injection.get('name', 'Message')}")
        
        except Exception as e:
            logger.error(f"    ❌ Injection error: {e}")
            result["error"] = str(e)
        
        return result
    
    def _generate_report(self, results: Dict[str, Any]):
        """Generate injection report"""
        logger.info("\n" + "=" * 70)
        logger.info("💉 MESSAGE INJECTION REPORT")
        logger.info("=" * 70)
        logger.info(f"Target: {results['target']}")
        logger.info(f"Mode: {results['mode']}")
        logger.info(f"Sandbox: {results['sandbox_mode']}")
        logger.info(f"Messages Injected: {results['messages_injected']}")
        logger.info("=" * 70)
        
        if results["injection_log"]:
            logger.info("\nInjection Log:")
            for entry in results["injection_log"]:
                status = "✅" if entry["success"] else "❌"
                logger.info(f"  {status} {entry['name']}: ID 0x{entry['arbitration_id']:03X}")
                if entry.get("response"):
                    logger.info(f"      Response: {entry['response']['data']}")


def run_message_injection(
    target: str = "ecu_simulator",
    injection_plan: Optional[List[Dict[str, Any]]] = None,
    sandbox_mode: bool = True
) -> Dict[str, Any]:
    """
    Main entry point for message injection
    """
    runner = MessageInjectionRunner()
    return runner.run(
        target=target,
        injection_plan=injection_plan,
        sandbox_mode=sandbox_mode
    )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    results = run_message_injection(sandbox_mode=True)
    print(f"\nInjection complete. Messages sent: {results['messages_injected']}")
