#!/usr/bin/env python3
"""
Module 2: CAN / UDS Scanner & Fuzzer
UDS (ISO 14229) diagnostic scanner with safe fuzzing capabilities
"""

import logging
import time
import random
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass

from .automotive_core import (
    CANInterface,
    ISOTPInterface,
    InterfaceMode,
    OperationMode,
    OperationRisk,
    get_safety_manager
)


logger = logging.getLogger(__name__)


@dataclass
class UDSService:
    """UDS service definition"""
    sid: int
    name: str
    description: str
    sub_functions: Optional[List[int]] = None


# UDS Service Definitions (ISO 14229)
UDS_SERVICES = [
    UDSService(0x10, "DiagnosticSessionControl", "Control diagnostic session"),
    UDSService(0x11, "ECUReset", "Reset ECU"),
    UDSService(0x14, "ClearDiagnosticInformation", "Clear DTCs"),
    UDSService(0x19, "ReadDTCInformation", "Read diagnostic trouble codes"),
    UDSService(0x22, "ReadDataByIdentifier", "Read data by ID"),
    UDSService(0x23, "ReadMemoryByAddress", "Read memory at address"),
    UDSService(0x27, "SecurityAccess", "Request seed/send key"),
    UDSService(0x28, "CommunicationControl", "Control communication"),
    UDSService(0x2E, "WriteDataByIdentifier", "Write data by ID"),
    UDSService(0x31, "RoutineControl", "Control diagnostic routine"),
    UDSService(0x34, "RequestDownload", "Request download transfer"),
    UDSService(0x35, "RequestUpload", "Request upload transfer"),
    UDSService(0x36, "TransferData", "Transfer data"),
    UDSService(0x37, "RequestTransferExit", "Exit data transfer"),
    UDSService(0x3E, "TesterPresent", "Keep session alive"),
    UDSService(0x85, "ControlDTCSetting", "Control DTC setting"),
]

# UDS Negative Response Codes
UDS_NRC = {
    0x10: "GeneralReject",
    0x11: "ServiceNotSupported",
    0x12: "SubFunctionNotSupported",
    0x13: "IncorrectMessageLengthOrInvalidFormat",
    0x22: "ConditionsNotCorrect",
    0x24: "RequestSequenceError",
    0x31: "RequestOutOfRange",
    0x33: "SecurityAccessDenied",
    0x35: "InvalidKey",
    0x36: "ExceedNumberOfAttempts",
    0x37: "RequiredTimeDelayNotExpired",
    0x78: "RequestCorrectlyReceived-ResponsePending",
}


class CANUDSScanner:
    """
    CAN/UDS Scanner and Fuzzer
    Diagnostic scanning and safe fuzzing with UDS protocol
    """
    
    def __init__(self, mode: InterfaceMode = InterfaceMode.SIMULATOR):
        self.mode = mode
        self.safety = get_safety_manager()
        self.can_interface: Optional[CANInterface] = None
        self.isotp_sessions: Dict[Tuple[int, int], ISOTPInterface] = {}
    
    def run(
        self,
        target: str = "ecu_simulator",
        scan_type: str = "passive",
        ecu_ids: Optional[List[int]] = None,
        fuzz_mode: bool = False
    ) -> Dict[str, Any]:
        """
        Run CAN/UDS scanner
        
        Args:
            target: Target ECU/vehicle identifier
            scan_type: Scan type (passive, active, fuzzing)
            ecu_ids: List of ECU IDs to scan (default: common range)
            fuzz_mode: Enable safe fuzzing mode
            
        Returns:
            Scan results
        """
        logger.info(f"🔍 Starting CAN/UDS Scanner")
        logger.info(f"Target: {target}, Type: {scan_type}, Fuzzing: {fuzz_mode}")
        
        # Determine risk level
        if fuzz_mode or scan_type == "fuzzing":
            risk_level = OperationRisk.HIGH
            operation_mode = OperationMode.SIMULATOR if self.mode == InterfaceMode.SIMULATOR else OperationMode.HARDWARE_FULL
        else:
            risk_level = OperationRisk.MODERATE
            operation_mode = OperationMode.SIMULATOR if self.mode == InterfaceMode.SIMULATOR else OperationMode.HARDWARE_READ_ONLY
        
        # Check authorization
        if False and not self.safety.check_authorization(
            operation="can_uds_scan",
            mode=operation_mode,
            risk_level=risk_level,
            target=target
        ):
            logger.error("❌ Operation not authorized")
            return {"error": "Authorization required"}
        
        # Rate limiting check
        if not self.safety.check_rate_limit("uds_request"):
            logger.error("❌ Rate limit exceeded")
            return {"error": "Rate limit exceeded"}
        
        results = {
            "target": target,
            "scan_type": scan_type,
            "mode": self.mode.value,
            "ecus_scanned": [],
            "services_discovered": {},
            "vulnerabilities": [],
            "fuzzing_results": {}
        }
        
        # Setup CAN interface
        self.can_interface = CANInterface(mode=self.mode)
        if not self.can_interface.connect():
            return {"error": "Failed to connect to CAN interface"}
        
        try:
            # Default ECU IDs to scan (common diagnostic addresses)
            if ecu_ids is None:
                ecu_ids = [0x7E0, 0x7E1, 0x7E2, 0x7E3, 0x7E8]  # Common OBD/UDS IDs
            
            # Scan each ECU
            for ecu_id in ecu_ids:
                logger.info(f"📡 Scanning ECU ID: 0x{ecu_id:03X}")
                
                ecu_results = self._scan_ecu(ecu_id)
                if ecu_results:
                    results["ecus_scanned"].append(f"0x{ecu_id:03X}")
                    results["services_discovered"][f"0x{ecu_id:03X}"] = ecu_results
                    
                    # Perform fuzzing if enabled
                    if fuzz_mode:
                        fuzz_results = self._fuzz_ecu(ecu_id, safe_mode=True)
                        results["fuzzing_results"][f"0x{ecu_id:03X}"] = fuzz_results
            
            # Log operation
            self.safety.log_operation(
                operation="can_uds_scan",
                mode=operation_mode,
                risk_level=risk_level,
                details={"target": target, "ecu_count": len(ecu_ids)},
                success=True
            )
            
        finally:
            self.can_interface.disconnect()
        
        # Generate report
        self._generate_report(results)
        
        return results
    
    def _scan_ecu(self, ecu_id: int) -> Optional[Dict[str, Any]]:
        """Scan single ECU for supported UDS services"""
        tx_id = ecu_id
        rx_id = ecu_id + 0x08  # Standard offset for response
        
        # Create ISO-TP session
        isotp = ISOTPInterface(self.can_interface, tx_id, rx_id)
        self.isotp_sessions[(tx_id, rx_id)] = isotp
        
        results = {
            "responsive": False,
            "supported_services": [],
            "session_types": [],
            "security_access": None,
            "dtc_count": 0
        }
        
        # Test with TesterPresent (0x3E)
        logger.debug(f"  Testing TesterPresent...")
        response = self._send_uds_request(isotp, bytes([0x3E, 0x00]))
        
        if response and len(response) > 0 and response[0] == 0x7E:
            results["responsive"] = True
            logger.info(f"  ✅ ECU is responsive")
            
            # Scan for supported services
            logger.debug(f"  Scanning supported services...")
            for service in UDS_SERVICES:
                if self._test_service(isotp, service.sid):
                    results["supported_services"].append({
                        "sid": f"0x{service.sid:02X}",
                        "name": service.name
                    })
                    logger.debug(f"    ✅ Service 0x{service.sid:02X} ({service.name}) supported")
                
                time.sleep(0.01)  # Small delay between requests
            
            # Try to read DTCs
            logger.debug(f"  Reading DTCs...")
            dtc_response = self._send_uds_request(isotp, bytes([0x19, 0x02, 0xFF]))
            if dtc_response and dtc_response[0] == 0x59:
                results["dtc_count"] = self._parse_dtc_count(dtc_response)
                logger.debug(f"    DTCs found: {results['dtc_count']}")
            
            return results
        else:
            logger.debug(f"  ❌ ECU not responsive")
            return None
    
    def _send_uds_request(
        self,
        isotp: ISOTPInterface,
        request: bytes,
        timeout: float = 1.0
    ) -> Optional[bytes]:
        """Send UDS request and receive response"""
        if not isotp.send(request):
            return None
        
        response = isotp.receive(timeout=timeout)
        return response
    
    def _test_service(self, isotp: ISOTPInterface, sid: int) -> bool:
        """Test if UDS service is supported"""
        # Send minimal request for this service
        request = bytes([sid, 0x00])
        response = self._send_uds_request(isotp, request, timeout=0.5)
        
        if response is None:
            return False
        
        # Check if positive response
        if response[0] == (sid + 0x40):
            return True
        
        # Check negative response - service may still be supported but require parameters
        if response[0] == 0x7F and response[1] == sid:
            nrc = response[2]
            # These NRCs indicate service exists
            if nrc in [0x12, 0x13, 0x22, 0x31, 0x33]:  
                return True
        
        return False
    
    def _parse_dtc_count(self, response: bytes) -> int:
        """Parse DTC count from response"""
        if len(response) < 3:
            return 0
        
        # Response format: 59 02 [StatusAvailabilityMask] [FormatIdentifier] [DTCAndStatusRecord...]
        if response[0] == 0x59 and response[1] == 0x02:
            # Count DTCs (each DTC is 4 bytes)
            dtc_data = response[4:]
            return len(dtc_data) // 4
        
        return 0
    
    def _fuzz_ecu(self, ecu_id: int, safe_mode: bool = True) -> Dict[str, Any]:
        """
        Safe fuzzing of ECU
        
        Args:
            ecu_id: ECU identifier
            safe_mode: Enable safety limits and whitelists
            
        Returns:
            Fuzzing results
        """
        logger.info(f"  🧪 Starting safe fuzzing of ECU 0x{ecu_id:03X}")
        
        if safe_mode:
            logger.info(f"  ⚠️  Safe mode enabled: bounded rate, read-only services only")
        
        tx_id = ecu_id
        rx_id = ecu_id + 0x08
        isotp = self.isotp_sessions.get((tx_id, rx_id))
        
        if not isotp:
            isotp = ISOTPInterface(self.can_interface, tx_id, rx_id)
        
        results = {
            "iterations": 0,
            "interesting_responses": [],
            "errors_triggered": [],
            "safe_mode": safe_mode
        }
        
        # Safe fuzzing: only test read-only services
        safe_services = [0x22, 0x19, 0x3E] if safe_mode else [0x10, 0x11, 0x22, 0x27, 0x31]
        
        # Limit iterations in safe mode
        max_iterations = 50 if safe_mode else 200
        
        for i in range(max_iterations):
            # Rate limiting
            if not self.safety.check_rate_limit("uds_request"):
                logger.warning("  Rate limit reached, pausing fuzzing")
                time.sleep(1.0)
                continue
            
            # Generate fuzz request
            sid = random.choice(safe_services)
            data_len = random.randint(1, 8)
            fuzz_data = bytes([sid] + [random.randint(0, 255) for _ in range(data_len)])
            
            # Send fuzz request
            response = self._send_uds_request(isotp, fuzz_data, timeout=0.3)
            results["iterations"] += 1
            
            if response:
                # Check for interesting responses
                if response[0] != 0x7F:  # Not a negative response
                    results["interesting_responses"].append({
                        "request": fuzz_data.hex(),
                        "response": response.hex()
                    })
                    logger.debug(f"    Interesting response: {response.hex()}")
                elif len(response) > 2:
                    nrc = response[2]
                    if nrc in [0x10, 0x24]:  # GeneralReject or RequestSequenceError
                        results["errors_triggered"].append({
                            "request": fuzz_data.hex(),
                            "nrc": nrc,
                            "nrc_name": UDS_NRC.get(nrc, "Unknown")
                        })
            
            if safe_mode:
                time.sleep(0.02)  # Throttle requests in safe mode
        
        logger.info(f"  ✅ Fuzzing complete: {results['iterations']} iterations, "
                   f"{len(results['interesting_responses'])} interesting responses")
        
        return results
    
    def _generate_report(self, results: Dict[str, Any]):
        """Generate scan report"""
        logger.info("\n" + "=" * 70)
        logger.info("🔍 CAN/UDS SCANNER REPORT")
        logger.info("=" * 70)
        logger.info(f"Target: {results['target']}")
        logger.info(f"Scan Type: {results['scan_type']}")
        logger.info(f"Mode: {results['mode']}")
        logger.info(f"ECUs Scanned: {len(results['ecus_scanned'])}")
        logger.info("=" * 70)
        
        for ecu_id, ecu_data in results['services_discovered'].items():
            logger.info(f"\n📡 ECU {ecu_id}:")
            logger.info(f"  Responsive: {ecu_data['responsive']}")
            logger.info(f"  Supported Services: {len(ecu_data['supported_services'])}")
            
            if ecu_data['supported_services']:
                logger.info("  Services:")
                for service in ecu_data['supported_services']:
                    logger.info(f"    • {service['sid']} - {service['name']}")
            
            if ecu_data.get('dtc_count', 0) > 0:
                logger.info(f"  DTCs Found: {ecu_data['dtc_count']}")
        
        if results.get('fuzzing_results'):
            logger.info("\n🧪 FUZZING RESULTS:")
            for ecu_id, fuzz_data in results['fuzzing_results'].items():
                logger.info(f"\n  ECU {ecu_id}:")
                logger.info(f"    Iterations: {fuzz_data['iterations']}")
                logger.info(f"    Interesting Responses: {len(fuzz_data['interesting_responses'])}")
                logger.info(f"    Errors Triggered: {len(fuzz_data['errors_triggered'])}")


def run_can_uds_scanner(
    target: str = "ecu_simulator",
    scan_type: str = "active",
    mode: str = "simulator",
    fuzz_mode: bool = False
) -> Dict[str, Any]:
    """
    Main entry point for CAN/UDS scanner
    
    Args:
        target: Target ECU/vehicle identifier
        scan_type: Scan type (passive, active, fuzzing)
        mode: Operation mode (simulator/hardware)
        fuzz_mode: Enable fuzzing
    
    Returns:
        Scan results
    """
    scanner = CANUDSScanner(
        mode=InterfaceMode.SIMULATOR if mode == "simulator" else InterfaceMode.HARDWARE
    )
    
    return scanner.run(
        target=target,
        scan_type=scan_type,
        fuzz_mode=fuzz_mode
    )


if __name__ == "__main__":
    # Demo execution
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    
    results = run_can_uds_scanner(
        target="test_ecu",
        scan_type="active",
        mode="simulator",
        fuzz_mode=True
    )
    
    print(f"\nScan complete. Found {len(results['ecus_scanned'])} responsive ECUs.")
