"""
Automotive Core Infrastructure
Shared components for vehicle security testing
"""

from .safety_manager import (
    AutomotiveSafetyManager,
    get_safety_manager,
    OperationMode,
    OperationRisk,
    AuthorizationToken
)

from .vehicle_interface import (
    VehicleBusInterface,
    CANInterface,
    LINInterface,
    FlexRayInterface,
    ISOTPInterface,
    BusType,
    InterfaceMode,
    CANMessage,
    LINMessage,
    FlexRayFrame
)

__all__ = [
    'AutomotiveSafetyManager',
    'get_safety_manager',
    'OperationMode',
    'OperationRisk',
    'AuthorizationToken',
    'VehicleBusInterface',
    'CANInterface',
    'LINInterface',
    'FlexRayInterface',
    'ISOTPInterface',
    'BusType',
    'InterfaceMode',
    'CANMessage',
    'LINMessage',
    'FlexRayFrame',
]
