#!/usr/bin/env python3
"""
Execution Adapter - Execute modules with collected parameters
Handles different execution types: argparse, class-based, subprocess
"""

import sys
import importlib
import subprocess
import logging
from typing import Dict, Any, Optional
from pathlib import Path
from cerberus_agents.module_registry import ModuleSchema

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ExecutionAdapter:
    """Adapts execution for different module types"""
    
    def __init__(self):
        self.last_result = None
    
    def execute_module(self, schema: ModuleSchema, params: Dict[str, Any]) -> bool:
        """Execute a module with collected parameters"""
        print(f"\n{'='*70}")
        print(f"🚀 EXECUTING: {schema.display_name}")
        print(f"{'='*70}\n")
        
        # Filter out any ==SUPPRESS== values that slipped through
        params = {k: v for k, v in params.items() if v != '==SUPPRESS=='}
        
        try:
            if schema.execution_type == 'argparse':
                return self._execute_argparse_module(schema, params)
            elif schema.execution_type == 'class':
                return self._execute_class_module(schema, params)
            elif schema.execution_type == 'subprocess':
                return self._execute_subprocess_module(schema, params)
            else:
                logger.error(f"Unknown execution type: {schema.execution_type}")
                return False
        except Exception as e:
            logger.error(f"❌ Execution failed: {e}", exc_info=True)
            return False
    
    def _execute_argparse_module(self, schema: ModuleSchema, params: Dict[str, Any]) -> bool:
        """Execute module with argparse-style main function"""
        try:
            # Import module
            module = importlib.import_module(f'cerberus_agents.{schema.module_name}')
            
            if not hasattr(module, 'main'):
                logger.error(f"Module {schema.module_name} has no main() function")
                return False
            
            # Build argument list
            args = []
            for param_name, param_value in params.items():
                # Skip SUPPRESS values
                if param_value == '==SUPPRESS==':
                    continue
                    
                # Find parameter info to get the correct CLI flag and action type
                param_info = None
                for p in schema.parameters:
                    if p.name == param_name:
                        param_info = p
                        break
                
                # Skip if parameter not found in schema (like 'authorized' which modules don't accept)
                if not param_info:
                    logger.debug(f"Parameter '{param_name}' not found in schema for {schema.module_name}, skipping")
                    continue
                
                # Determine CLI flag to use (prefer longest --flag, error if missing for argparse modules)
                if param_info.cli_flags:
                    # Prefer longest --flag
                    long_flags = [f for f in param_info.cli_flags if f.startswith('--')]
                    arg_name = long_flags[0] if long_flags else param_info.cli_flags[0]
                else:
                    # Missing CLI flags - use fallback with strong warning
                    if schema.execution_type == 'argparse':
                        logger.error(f"SCHEMA DEFECT: Argparse module '{schema.module_name}' parameter '{param_name}' missing CLI flags - using fallback --{param_name.replace('_', '-')}")
                    else:
                        logger.warning(f"Parameter '{param_name}' has no CLI flags in schema, using fallback conversion")
                    arg_name = f"--{param_name.replace('_', '-')}"
                
                # Handle boolean flags based on action type
                if isinstance(param_value, bool) and param_info:
                    if param_info.action == 'store_true':
                        # Add flag only if value is True
                        if param_value:
                            args.append(arg_name)
                    elif param_info.action == 'store_false':
                        # Add flag only if value is False (inverts the default True)
                        if not param_value:
                            args.append(arg_name)
                    elif param_info.action == 'store_const':
                        # Add flag if value matches the expected behavior
                        if param_value:
                            args.append(arg_name)
                elif param_value is not None:
                    # Regular parameter with value
                    if isinstance(param_value, list):
                        # Handle list parameters based on action type
                        if param_info and param_info.action == 'append':
                            # For append action: --flag item1 --flag item2
                            for item in param_value:
                                args.append(arg_name)
                                args.append(str(item))
                        else:
                            # For nargs ('+', '*', etc): --flag item1 item2 item3
                            args.append(arg_name)
                            for item in param_value:
                                args.append(str(item))
                    else:
                        # Single value parameter
                        args.append(arg_name)
                        args.append(str(param_value))
            
            # Execute using subprocess to capture stdout/stderr
            cmd = [sys.executable, '-m', f'cerberus_agents.{schema.module_name}'] + args
            
            logger.info(f"Executing: {' '.join(cmd)}")
            
            # Execute and stream output directly to console
            result = subprocess.run(
                cmd,
                stdout=None,  # Stream to console
                stderr=None,  # Stream to console
                text=True
            )
            
            if result.returncode == 0:
                logger.info("✅ Module execution completed successfully")
                return True
            else:
                logger.warning(f"⚠️  Module exited with code {result.returncode}")
                return True  # Still return True since module ran
            
        except SystemExit as e:
            # Many argparse modules call sys.exit()
            if e.code == 0:
                logger.info("✅ Module execution completed (exit code 0)")
                return True
            else:
                logger.error(f"❌ Module exited with code {e.code}")
                return False
        except Exception as e:
            logger.error(f"❌ Execution error: {e}", exc_info=True)
            return False
    
    def _execute_class_module(self, schema: ModuleSchema, params: Dict[str, Any]) -> bool:
        """Execute class-based module"""
        try:
            # Import module
            module = importlib.import_module(f'cerberus_agents.{schema.module_name}')
            
            # Find primary class
            primary_class = None
            for name, obj in vars(module).items():
                if isinstance(obj, type) and obj.__module__ == module.__name__:
                    # Look for class with similar name to module
                    if schema.module_name.replace('_', '').lower() in name.lower():
                        primary_class = obj
                        break
            
            if not primary_class:
                # Use first class defined in module
                for name, obj in vars(module).items():
                    if isinstance(obj, type) and obj.__module__ == module.__name__:
                        primary_class = obj
                        break
            
            if not primary_class:
                logger.error(f"No suitable class found in {schema.module_name}")
                return False
            
            logger.info(f"Instantiating {primary_class.__name__} with parameters...")
            
            # Instantiate class
            instance = primary_class(**params)
            
            # Look for run/execute/scan method
            for method_name in ['run', 'execute', 'scan', 'start', 'perform_scan']:
                if hasattr(instance, method_name):
                    method = getattr(instance, method_name)
                    logger.info(f"Executing {primary_class.__name__}.{method_name}()")
                    result = method()
                    logger.info("✅ Module execution completed")
                    self.last_result = result
                    return True
            
            logger.warning("⚠️  No execution method found (run/execute/scan). Module instantiated but not executed.")
            return True
            
        except Exception as e:
            logger.error(f"❌ Class execution error: {e}", exc_info=True)
            return False
    
    def _execute_subprocess_module(self, schema: ModuleSchema, params: Dict[str, Any]) -> bool:
        """Execute external tool via subprocess"""
        try:
            # Build command
            cmd = [schema.entrypoint]
            
            for param_name, param_value in params.items():
                if param_name == 'authorized':
                    continue
                if param_value is not None:
                    cmd.extend([f"--{param_name.replace('_', '-')}", str(param_value)])
            
            logger.info(f"Executing subprocess: {' '.join(cmd)}")
            
            # Execute with real-time output
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            # Stream output
            if process.stdout:
                for line in process.stdout:
                    print(line, end='')
            
            process.wait()
            
            if process.returncode == 0:
                logger.info("✅ Subprocess execution completed")
                return True
            else:
                logger.error(f"❌ Subprocess failed with exit code {process.returncode}")
                return False
                
        except FileNotFoundError:
            logger.error(f"❌ Command not found: {schema.entrypoint}")
            logger.info("💡 This tool may require additional installation")
            return False
        except Exception as e:
            logger.error(f"❌ Subprocess error: {e}", exc_info=True)
            return False
    
    def get_last_result(self) -> Any:
        """Get result from last execution"""
        return self.last_result


if __name__ == "__main__":
    # Test execution adapter
    from cerberus_agents.module_registry import ModuleSchema, ParameterInfo
    
    test_schema = ModuleSchema(
        module_name="network_scanner_advanced",
        display_name="Network Scanner",
        description="Advanced network scanning",
        category="network",
        parameters=[
            ParameterInfo("target", "str", True, None, "Target to scan"),
            ParameterInfo("ports", "str", False, "1-1000", "Port range"),
        ],
        execution_type="argparse",
        entrypoint="main"
    )
    
    test_params = {
        "target": "192.168.1.1",
        "ports": "80,443",
        "authorized": True
    }
    
    adapter = ExecutionAdapter()
    success = adapter.execute_module(test_schema, test_params)
    print(f"\nExecution {'succeeded' if success else 'failed'}")
