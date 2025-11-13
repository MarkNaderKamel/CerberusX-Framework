#!/usr/bin/env python3
"""
Vehicle Network Interface & Abstraction Layer
Unified API for CAN, CAN-FD, LIN, FlexRay, and ISO-TP
"""

import logging
import time
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass
from enum import Enum


logger = logging.getLogger(__name__)


class BusType(Enum):
    """Supported vehicle bus types"""
    CAN = "can"
    CAN_FD = "can_fd"
    LIN = "lin"
    FLEXRAY = "flexray"
    ISO_TP = "iso_tp"
    ETHERNET = "ethernet"


class InterfaceMode(Enum):
    """Interface operation modes"""
    SIMULATOR = "simulator"
    HARDWARE = "hardware"


@dataclass
class CANMessage:
    """CAN message structure"""
    arbitration_id: int
    data: bytes
    is_extended_id: bool = False
    is_fd: bool = False
    timestamp: Optional[float] = None
    channel: Optional[str] = None
    
    def __repr__(self):
        data_hex = ' '.join(f'{b:02X}' for b in self.data)
        return f"CANMessage(ID=0x{self.arbitration_id:03X}, Data=[{data_hex}], FD={self.is_fd})"


@dataclass
class LINMessage:
    """LIN message structure"""
    frame_id: int
    data: bytes
    timestamp: Optional[float] = None
    
    def __repr__(self):
        data_hex = ' '.join(f'{b:02X}' for b in self.data)
        return f"LINMessage(ID=0x{self.frame_id:02X}, Data=[{data_hex}])"


@dataclass
class FlexRayFrame:
    """FlexRay frame structure"""
    slot_id: int
    cycle: int
    data: bytes
    channel: str
    timestamp: Optional[float] = None


class VehicleBusInterface(ABC):
    """Abstract base class for vehicle bus interfaces"""
    
    def __init__(self, bus_type: BusType, mode: InterfaceMode = InterfaceMode.SIMULATOR):
        self.bus_type = bus_type
        self.mode = mode
        self.is_connected = False
        self.message_callbacks: List[Callable] = []
    
    @abstractmethod
    def connect(self, **kwargs) -> bool:
        """Connect to vehicle bus"""
        pass
    
    @abstractmethod
    def disconnect(self):
        """Disconnect from vehicle bus"""
        pass
    
    @abstractmethod
    def send(self, message: Any) -> bool:
        """Send message on bus"""
        pass
    
    @abstractmethod
    def receive(self, timeout: Optional[float] = None) -> Optional[Any]:
        """Receive message from bus"""
        pass
    
    def register_callback(self, callback: Callable):
        """Register message receive callback"""
        self.message_callbacks.append(callback)
    
    def _notify_callbacks(self, message: Any):
        """Notify all registered callbacks"""
        for callback in self.message_callbacks:
            try:
                callback(message)
            except Exception as e:
                logger.error(f"Callback error: {e}")


class CANInterface(VehicleBusInterface):
    """
    CAN and CAN-FD interface implementation
    Supports both simulator and hardware modes
    """
    
    def __init__(
        self,
        mode: InterfaceMode = InterfaceMode.SIMULATOR,
        channel: str = "vcan0",
        bitrate: int = 500000,
        fd_enabled: bool = False
    ):
        super().__init__(BusType.CAN_FD if fd_enabled else BusType.CAN, mode)
        self.channel = channel
        self.bitrate = bitrate
        self.fd_enabled = fd_enabled
        self.bus = None
        self.simulator_messages: List[CANMessage] = []
    
    def connect(self, **kwargs) -> bool:
        """Connect to CAN interface"""
        try:
            if self.mode == InterfaceMode.SIMULATOR:
                logger.info(f"✅ Connected to CAN simulator (channel: {self.channel})")
                self.is_connected = True
                self._start_simulator()
                return True
            else:
                # Hardware mode - requires python-can
                try:
                    import can
                    
                    # Try to create CAN bus
                    self.bus = can.interface.Bus(
                        channel=self.channel,
                        bustype='socketcan',
                        bitrate=self.bitrate,
                        fd=self.fd_enabled
                    )
                    
                    logger.info(f"✅ Connected to CAN hardware (channel: {self.channel}, "
                               f"bitrate: {self.bitrate}, FD: {self.fd_enabled})")
                    self.is_connected = True
                    return True
                    
                except ImportError:
                    logger.error("python-can not installed, falling back to simulator")
                    self.mode = InterfaceMode.SIMULATOR
                    return self.connect(**kwargs)
                except Exception as e:
                    logger.error(f"Failed to connect to CAN hardware: {e}")
                    logger.info("Falling back to simulator mode")
                    self.mode = InterfaceMode.SIMULATOR
                    return self.connect(**kwargs)
                    
        except Exception as e:
            logger.error(f"Failed to connect to CAN interface: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from CAN interface"""
        if self.bus:
            try:
                self.bus.shutdown()
            except:
                pass
        
        self.is_connected = False
        logger.info(f"Disconnected from CAN interface ({self.mode.value})")
    
    def send(self, message: CANMessage) -> bool:
        """Send CAN message"""
        if not self.is_connected:
            logger.error("Not connected to CAN interface")
            return False
        
        try:
            if self.mode == InterfaceMode.SIMULATOR:
                # Simulator mode - just log
                logger.debug(f"📤 [SIM] Sending: {message}")
                self.simulator_messages.append(message)
                return True
            else:
                # Hardware mode
                import can
                
                can_msg = can.Message(
                    arbitration_id=message.arbitration_id,
                    data=message.data,
                    is_extended_id=message.is_extended_id,
                    is_fd=message.is_fd
                )
                
                self.bus.send(can_msg)
                logger.debug(f"📤 [HW] Sent: {message}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to send CAN message: {e}")
            return False
    
    def receive(self, timeout: Optional[float] = 1.0) -> Optional[CANMessage]:
        """Receive CAN message"""
        if not self.is_connected:
            logger.error("Not connected to CAN interface")
            return None
        
        try:
            if self.mode == InterfaceMode.SIMULATOR:
                # Simulator mode - return simulated messages
                if self.simulator_messages:
                    msg = self.simulator_messages.pop(0)
                    logger.debug(f"📥 [SIM] Received: {msg}")
                    self._notify_callbacks(msg)
                    return msg
                return None
            else:
                # Hardware mode
                can_msg = self.bus.recv(timeout=timeout)
                if can_msg:
                    message = CANMessage(
                        arbitration_id=can_msg.arbitration_id,
                        data=can_msg.data,
                        is_extended_id=can_msg.is_extended_id,
                        is_fd=can_msg.is_fd,
                        timestamp=can_msg.timestamp,
                        channel=self.channel
                    )
                    logger.debug(f"📥 [HW] Received: {message}")
                    self._notify_callbacks(message)
                    return message
                return None
                
        except Exception as e:
            logger.error(f"Failed to receive CAN message: {e}")
            return None
    
    def _start_simulator(self):
        """Start CAN message simulator with typical automotive traffic"""
        # Simulate common automotive CAN messages
        self.simulator_messages = [
            CANMessage(0x100, bytes([0x00, 0x00, 0x00, 0x00])),  # Engine RPM
            CANMessage(0x200, bytes([0x00, 0x00])),  # Vehicle speed
            CANMessage(0x300, bytes([0x00])),  # Gear position
            CANMessage(0x400, bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00])),  # Wheel speeds
            CANMessage(0x500, bytes([0x00, 0x00])),  # Steering angle
        ]


class LINInterface(VehicleBusInterface):
    """LIN bus interface implementation"""
    
    def __init__(self, mode: InterfaceMode = InterfaceMode.SIMULATOR, device: str = "/dev/ttyUSB0"):
        super().__init__(BusType.LIN, mode)
        self.device = device
        self.simulator_messages: List[LINMessage] = []
    
    def connect(self, **kwargs) -> bool:
        """Connect to LIN interface"""
        if self.mode == InterfaceMode.SIMULATOR:
            logger.info(f"✅ Connected to LIN simulator")
            self.is_connected = True
            self._start_simulator()
            return True
        else:
            logger.warning("LIN hardware mode not yet implemented, using simulator")
            self.mode = InterfaceMode.SIMULATOR
            return self.connect(**kwargs)
    
    def disconnect(self):
        """Disconnect from LIN interface"""
        self.is_connected = False
        logger.info(f"Disconnected from LIN interface")
    
    def send(self, message: LINMessage) -> bool:
        """Send LIN message"""
        if not self.is_connected:
            return False
        
        logger.debug(f"📤 [LIN SIM] Sending: {message}")
        return True
    
    def receive(self, timeout: Optional[float] = 1.0) -> Optional[LINMessage]:
        """Receive LIN message"""
        if not self.is_connected:
            return None
        
        if self.simulator_messages:
            msg = self.simulator_messages.pop(0)
            logger.debug(f"📥 [LIN SIM] Received: {msg}")
            self._notify_callbacks(msg)
            return msg
        return None
    
    def _start_simulator(self):
        """Start LIN message simulator"""
        self.simulator_messages = [
            LINMessage(0x01, bytes([0x00, 0x00, 0x00, 0x00])),
            LINMessage(0x02, bytes([0x00, 0x00])),
        ]


class FlexRayInterface(VehicleBusInterface):
    """FlexRay interface implementation"""
    
    def __init__(self, mode: InterfaceMode = InterfaceMode.SIMULATOR):
        super().__init__(BusType.FLEXRAY, mode)
        self.simulator_frames: List[FlexRayFrame] = []
    
    def connect(self, **kwargs) -> bool:
        """Connect to FlexRay interface"""
        if self.mode == InterfaceMode.SIMULATOR:
            logger.info(f"✅ Connected to FlexRay simulator")
            self.is_connected = True
            self._start_simulator()
            return True
        else:
            logger.warning("FlexRay hardware mode not yet implemented, using simulator")
            self.mode = InterfaceMode.SIMULATOR
            return self.connect(**kwargs)
    
    def disconnect(self):
        """Disconnect from FlexRay interface"""
        self.is_connected = False
        logger.info(f"Disconnected from FlexRay interface")
    
    def send(self, message: FlexRayFrame) -> bool:
        """Send FlexRay frame"""
        if not self.is_connected:
            return False
        
        logger.debug(f"📤 [FlexRay SIM] Sending frame in slot {message.slot_id}")
        return True
    
    def receive(self, timeout: Optional[float] = 1.0) -> Optional[FlexRayFrame]:
        """Receive FlexRay frame"""
        if not self.is_connected:
            return None
        
        if self.simulator_frames:
            frame = self.simulator_frames.pop(0)
            logger.debug(f"📥 [FlexRay SIM] Received frame from slot {frame.slot_id}")
            self._notify_callbacks(frame)
            return frame
        return None
    
    def _start_simulator(self):
        """Start FlexRay simulator"""
        self.simulator_frames = [
            FlexRayFrame(1, 0, bytes([0x00] * 8), "A"),
            FlexRayFrame(2, 0, bytes([0x00] * 8), "B"),
        ]


class ISOTPInterface:
    """
    ISO-TP (ISO 15765-2) transport layer for UDS
    Handles message segmentation and reassembly
    """
    
    def __init__(self, can_interface: CANInterface, tx_id: int, rx_id: int):
        self.can = can_interface
        self.tx_id = tx_id
        self.rx_id = rx_id
        self.receive_buffer = bytearray()
        self.sequence_number = 0
    
    def send(self, data: bytes) -> bool:
        """Send ISO-TP message (with segmentation if needed)"""
        if len(data) <= 7:
            # Single frame
            message = CANMessage(
                arbitration_id=self.tx_id,
                data=bytes([len(data)]) + data
            )
            return self.can.send(message)
        else:
            # Multi-frame (first frame + consecutive frames)
            logger.info(f"ISO-TP multi-frame transmission ({len(data)} bytes)")
            
            # First frame
            first_frame = CANMessage(
                arbitration_id=self.tx_id,
                data=bytes([0x10 | ((len(data) >> 8) & 0x0F), len(data) & 0xFF]) + data[:6]
            )
            if not self.can.send(first_frame):
                return False
            
            # Consecutive frames
            offset = 6
            sn = 1
            while offset < len(data):
                chunk = data[offset:offset+7]
                consecutive_frame = CANMessage(
                    arbitration_id=self.tx_id,
                    data=bytes([0x20 | (sn & 0x0F)]) + chunk
                )
                if not self.can.send(consecutive_frame):
                    return False
                offset += 7
                sn = (sn + 1) % 16
                time.sleep(0.001)  # Small delay between frames
            
            return True
    
    def receive(self, timeout: float = 1.0) -> Optional[bytes]:
        """Receive ISO-TP message (with reassembly if needed)"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            msg = self.can.receive(timeout=0.1)
            if not msg or msg.arbitration_id != self.rx_id:
                continue
            
            # Parse frame type
            frame_type = (msg.data[0] >> 4) & 0x0F
            
            if frame_type == 0:  # Single frame
                length = msg.data[0] & 0x0F
                return bytes(msg.data[1:1+length])
            
            elif frame_type == 1:  # First frame
                length = ((msg.data[0] & 0x0F) << 8) | msg.data[1]
                self.receive_buffer = bytearray(msg.data[2:8])
                # Continue receiving consecutive frames
                
            elif frame_type == 2:  # Consecutive frame
                self.receive_buffer.extend(msg.data[1:8])
                # Check if complete
                if len(self.receive_buffer) >= length:
                    result = bytes(self.receive_buffer[:length])
                    self.receive_buffer.clear()
                    return result
        
        return None
