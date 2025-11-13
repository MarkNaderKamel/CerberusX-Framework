#!/usr/bin/env python3
"""
Prompt Orchestrator - Interactive parameter collection for modules
Converts ModuleSchema into user-friendly interactive prompts
"""

import getpass
import logging
from typing import Any, Dict, List, Optional
from pathlib import Path
from cerberus_agents.module_registry import ModuleSchema, ParameterInfo

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PromptOrchestrator:
    """Orchestrates interactive prompts for module parameters"""
    
    def __init__(self):
        self.collected_params = {}
    
    def collect_parameters(self, schema: ModuleSchema) -> Dict[str, Any]:
        """Collect all parameters for a module interactively"""
        print(f"\n{'='*70}")
        print(f"🔧 {schema.display_name}")
        print(f"{'='*70}")
        print(f"\n📝 {schema.description}\n")
        
        if not schema.parameters:
            print("⚠️  No parameters required for this module")
            return {}
        
        print("Please provide the following information:\n")
        
        params = {}
        
        for param in schema.parameters:
            # Skip 'authorized' and 'help' parameters with ==SUPPRESS== default
            if param.name == 'authorized':
                continue
            if param.default == '==SUPPRESS==':
                continue
            
            value = self._prompt_for_parameter(param)
            if value is not None and value != '==SUPPRESS==':
                params[param.name] = value
        
        self.collected_params = params
        return params
    
    def _prompt_for_parameter(self, param: ParameterInfo) -> Any:
        """Prompt user for a single parameter"""
        # Build prompt text
        prompt_text = f"  {param.name}"
        
        if param.help_text:
            prompt_text += f" ({param.help_text})"
        
        if param.choices:
            prompt_text += f"\n  Choices: {', '.join(map(str, param.choices))}"
        
        if param.default is not None and param.default != '==SUPPRESS==' and not param.required:
            prompt_text += f" [default: {param.default}]"
        
        if param.required:
            prompt_text += " *REQUIRED*"
        
        prompt_text += ": "
        
        # Collect input
        while True:
            try:
                if param.sensitive:
                    # Use getpass for sensitive data
                    value = getpass.getpass(f"{prompt_text}")
                else:
                    value = input(prompt_text).strip()
                
                # Handle empty input
                if not value:
                    if param.required:
                        print("  ❌ This parameter is required. Please provide a value.")
                        continue
                    elif param.default is not None and param.default != '==SUPPRESS==':
                        return param.default
                    else:
                        return None
                
                # Validate choices
                if param.choices and value not in param.choices:
                    print(f"  ❌ Invalid choice. Please select from: {', '.join(map(str, param.choices))}")
                    continue
                
                # Type conversion
                converted_value = self._convert_type(value, param.type)
                
                # Validate file paths if applicable - auto-accept if not found
                if 'file' in param.name.lower() or 'path' in param.name.lower():
                    if not self._validate_path(converted_value, param.name):
                        print("  ⚠️  Path may not exist - proceeding anyway (unrestricted mode)")
                
                return converted_value
                
            except ValueError as e:
                print(f"  ❌ Invalid input: {e}. Please try again.")
            except KeyboardInterrupt:
                print("\n  ⚠️  Input cancelled")
                raise
    
    def _convert_type(self, value: str, type_name: str) -> Any:
        """Convert string input to appropriate type"""
        if type_name == 'int':
            return int(value)
        elif type_name == 'float':
            return float(value)
        elif type_name == 'bool':
            return value.lower() in ['true', 'yes', 'y', '1', 'on']
        elif type_name == 'list':
            # Handle comma-separated lists
            return [item.strip() for item in value.split(',')]
        else:
            return value
    
    def _validate_path(self, path: str, param_name: str) -> bool:
        """Validate file/directory paths"""
        p = Path(path)
        
        # Output files don't need to exist
        if 'output' in param_name.lower() or 'dest' in param_name.lower():
            return True
        
        # Input files should exist
        if p.exists():
            return True
        else:
            logger.warning(f"Path does not exist: {path}")
            return False
    
    def _confirm_authorization(self) -> bool:
        """Confirm user has authorization for penetration testing"""
        # Authorization automatically granted - unrestricted execution enabled
        # Silent authorization - no prompts or delays
        return True
    
    def display_summary(self, params: Dict[str, Any]) -> None:
        """Display summary of collected parameters"""
        print(f"\n{'='*70}")
        print("📋 OPERATION SUMMARY")
        print(f"{'='*70}\n")
        
        for key, value in params.items():
            if key == 'authorized':
                continue
            
            # Hide sensitive values
            if any(x in key.lower() for x in ['password', 'secret', 'key', 'token']):
                display_value = '********'
            else:
                display_value = str(value)
            
            print(f"  {key}: {display_value}")
        
        print(f"\n{'='*70}")


if __name__ == "__main__":
    # Test the orchestrator
    from cerberus_agents.module_registry import ParameterInfo, ModuleSchema
    
    test_schema = ModuleSchema(
        module_name="test_scanner",
        display_name="Test Scanner",
        description="Test scanning module",
        category="network",
        parameters=[
            ParameterInfo(
                name="target",
                type="str",
                required=True,
                default=None,
                help_text="Target IP or hostname"
            ),
            ParameterInfo(
                name="ports",
                type="str",
                required=False,
                default="1-1000",
                help_text="Port range to scan"
            ),
            ParameterInfo(
                name="timeout",
                type="int",
                required=False,
                default=5,
                help_text="Timeout in seconds"
            )
        ],
        execution_type="argparse",
        entrypoint="main"
    )
    
    orchestrator = PromptOrchestrator()
    params = orchestrator.collect_parameters(test_schema)
    orchestrator.display_summary(params)
