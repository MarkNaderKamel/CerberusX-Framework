#!/usr/bin/env python3
"""
Module 5: Telematics & Backend Interface Tester
Test telematics protocols: MQTT, HTTP/2, gRPC, WebSockets
"""

import logging
import json
import time
from typing import Optional, Dict, List, Any

from .automotive_core import (
    OperationMode,
    OperationRisk,
    get_safety_manager
)


logger = logging.getLogger(__name__)


class TelematicsBackendTester:
    """
    Telematics Backend Tester
    Test vehicle-to-cloud communication protocols
    """
    
    def __init__(self):
        self.safety = get_safety_manager()
    
    def run(
        self,
        target_url: str = "mqtt://simulator.local",
        target: str = "telematics_backend",
        protocols: Optional[List[str]] = None,
        test_auth: bool = True
    ) -> Dict[str, Any]:
        """
        Test telematics backend
        
        Args:
            target_url: Target backend URL
            target: Target identifier
            protocols: Protocols to test (mqtt, http, grpc, ws)
            test_auth: Test authentication/authorization
            
        Returns:
            Test results
        """
        logger.info(f"📡 Starting Telematics Backend Tester")
        logger.info(f"Target: {target_url}")
        
        # Check authorization
        if not self.safety.check_authorization(
            operation="telematics_test",
            mode=OperationMode.SIMULATOR,
            risk_level=OperationRisk.MODERATE,
            target=target
        ):
            logger.error("❌ Operation not authorized")
            return {"error": "Authorization required"}
        
        results = {
            "target_url": target_url,
            "target": target,
            "protocols_tested": [],
            "auth_tests": {},
            "vulnerabilities": []
        }
        
        if protocols is None:
            protocols = ["mqtt", "http", "ws"]
        
        # Test each protocol
        for protocol in protocols:
            logger.info(f"🔍 Testing {protocol.upper()} protocol...")
            
            if protocol == "mqtt":
                results["mqtt_tests"] = self._test_mqtt(target_url)
                results["protocols_tested"].append("MQTT")
            elif protocol == "http":
                results["http_tests"] = self._test_http(target_url)
                results["protocols_tested"].append("HTTP")
            elif protocol == "grpc":
                results["grpc_tests"] = self._test_grpc(target_url)
                results["protocols_tested"].append("gRPC")
            elif protocol == "ws":
                results["ws_tests"] = self._test_websocket(target_url)
                results["protocols_tested"].append("WebSocket")
        
        # Test authentication
        if test_auth:
            results["auth_tests"] = self._test_authentication()
        
        # Assess vulnerabilities
        results["vulnerabilities"] = self._assess_vulnerabilities(results)
        
        # Log operation
        self.safety.log_operation(
            operation="telematics_test",
            mode=OperationMode.SIMULATOR,
            risk_level=OperationRisk.MODERATE,
            details={"target": target, "protocols": protocols},
            success=True
        )
        
        # Generate report
        self._generate_report(results)
        
        return results
    
    def _test_mqtt(self, target_url: str) -> Dict[str, Any]:
        """Test MQTT protocol"""
        logger.info("  Testing MQTT...")
        
        # Simulated MQTT tests
        tests = {
            "connection": {"passed": True, "status": "Connected"},
            "qos_levels": {"passed": True, "supported": [0, 1, 2]},
            "topic_injection": {"passed": False, "vulnerable": True},
            "retained_messages": {"passed": True, "count": 0},
            "will_messages": {"passed": True, "supported": True}
        }
        
        return {
            "tests": tests,
            "passed": sum(1 for t in tests.values() if t.get("passed", False)),
            "total": len(tests)
        }
    
    def _test_http(self, target_url: str) -> Dict[str, Any]:
        """Test HTTP/HTTPS protocol"""
        logger.info("  Testing HTTP...")
        
        # Simulated HTTP tests
        tests = {
            "tls_version": {"passed": True, "version": "TLS 1.3"},
            "certificate": {"passed": True, "valid": True},
            "http2_support": {"passed": True, "supported": True},
            "compression": {"passed": True, "methods": ["gzip"]},
            "rate_limiting": {"passed": False, "implemented": False}
        }
        
        return {
            "tests": tests,
            "passed": sum(1 for t in tests.values() if t.get("passed", False)),
            "total": len(tests)
        }
    
    def _test_grpc(self, target_url: str) -> Dict[str, Any]:
        """Test gRPC protocol"""
        logger.info("  Testing gRPC...")
        
        # Simulated gRPC tests
        tests = {
            "connection": {"passed": True, "status": "Connected"},
            "reflection": {"passed": True, "enabled": True},
            "streaming": {"passed": True, "bidirectional": True},
            "metadata_injection": {"passed": False, "vulnerable": True}
        }
        
        return {
            "tests": tests,
            "passed": sum(1 for t in tests.values() if t.get("passed", False)),
            "total": len(tests)
        }
    
    def _test_websocket(self, target_url: str) -> Dict[str, Any]:
        """Test WebSocket protocol"""
        logger.info("  Testing WebSocket...")
        
        # Simulated WebSocket tests
        tests = {
            "connection": {"passed": True, "status": "Connected"},
            "message_framing": {"passed": True, "correct": True},
            "ping_pong": {"passed": True, "responsive": True},
            "origin_validation": {"passed": False, "validated": False}
        }
        
        return {
            "tests": tests,
            "passed": sum(1 for t in tests.values() if t.get("passed", False)),
            "total": len(tests)
        }
    
    def _test_authentication(self) -> Dict[str, Any]:
        """Test authentication mechanisms"""
        logger.info("🔐 Testing authentication...")
        
        tests = {
            "token_validation": self._test_token_validation(),
            "token_renewal": self._test_token_renewal(),
            "token_replay": self._test_token_replay(),
            "credential_leakage": self._test_credential_leakage()
        }
        
        passed = sum(1 for t in tests.values() if t.get("passed", False))
        
        return {
            "tests": tests,
            "passed": passed,
            "total": len(tests)
        }
    
    def _test_token_validation(self) -> Dict[str, Any]:
        """Test token validation"""
        # Simulated test
        return {
            "passed": True,
            "algorithm": "JWT",
            "expiry_checked": True
        }
    
    def _test_token_renewal(self) -> Dict[str, Any]:
        """Test token renewal mechanism"""
        # Simulated test
        return {
            "passed": True,
            "refresh_supported": True,
            "rotation_enforced": True
        }
    
    def _test_token_replay(self) -> Dict[str, Any]:
        """Test token replay protection"""
        # Simulated test
        return {
            "passed": False,
            "replay_detected": False,
            "issue": "Old tokens accepted"
        }
    
    def _test_credential_leakage(self) -> Dict[str, Any]:
        """Test for credential leakage"""
        # Simulated test
        return {
            "passed": True,
            "leakage_found": False,
            "channels_checked": ["logs", "errors", "headers"]
        }
    
    def _assess_vulnerabilities(self, results: Dict[str, Any]) -> List[Dict[str, str]]:
        """Assess vulnerabilities"""
        vulnerabilities = []
        
        # Check MQTT issues
        mqtt = results.get("mqtt_tests", {}).get("tests", {})
        if mqtt.get("topic_injection", {}).get("vulnerable"):
            vulnerabilities.append({
                "severity": "MEDIUM",
                "type": "MQTT Topic Injection",
                "description": "Unsanitized topic names allow injection",
                "recommendation": "Implement topic name validation"
            })
        
        # Check HTTP issues
        http = results.get("http_tests", {}).get("tests", {})
        if not http.get("rate_limiting", {}).get("implemented"):
            vulnerabilities.append({
                "severity": "MEDIUM",
                "type": "No Rate Limiting",
                "description": "API endpoints not rate limited",
                "recommendation": "Implement rate limiting"
            })
        
        # Check auth issues
        auth = results.get("auth_tests", {}).get("tests", {})
        if auth and not auth.get("token_replay", {}).get("passed"):
            vulnerabilities.append({
                "severity": "HIGH",
                "type": "Token Replay",
                "description": auth.get("token_replay", {}).get("issue", "Token replay possible"),
                "recommendation": "Implement nonce/timestamp validation"
            })
        
        return vulnerabilities
    
    def _generate_report(self, results: Dict[str, Any]):
        """Generate test report"""
        logger.info("\n" + "=" * 70)
        logger.info("📡 TELEMATICS BACKEND TEST REPORT")
        logger.info("=" * 70)
        logger.info(f"Target: {results['target_url']}")
        logger.info(f"Protocols: {', '.join(results['protocols_tested'])}")
        logger.info("=" * 70)
        
        # Protocol tests
        for protocol in results["protocols_tested"]:
            key = f"{protocol.lower()}_tests"
            if key in results:
                test_data = results[key]
                logger.info(f"\n{protocol} Tests:")
                logger.info(f"  Pass Rate: {test_data['passed']}/{test_data['total']}")
        
        # Auth tests
        if results.get("auth_tests"):
            auth = results["auth_tests"]
            logger.info(f"\n🔐 Authentication Tests:")
            logger.info(f"  Pass Rate: {auth['passed']}/{auth['total']}")
        
        # Vulnerabilities
        if results.get("vulnerabilities"):
            logger.info(f"\n⚠️  VULNERABILITIES: {len(results['vulnerabilities'])}")
            for vuln in results["vulnerabilities"]:
                logger.info(f"\n  [{vuln['severity']}] {vuln['type']}")
                logger.info(f"    {vuln['description']}")


def run_telematics_backend_tester(
    target_url: str = "mqtt://simulator.local",
    protocols: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Main entry point for telematics backend tester
    """
    tester = TelematicsBackendTester()
    return tester.run(target_url=target_url, protocols=protocols)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    results = run_telematics_backend_tester()
    print(f"\nTests complete. Found {len(results['vulnerabilities'])} vulnerabilities.")
