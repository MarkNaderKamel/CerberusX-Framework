#!/usr/bin/env python3
"""
Module Registry - Auto-discovery and introspection of all Cerberus Agents modules
Dynamically extracts parameter requirements from modules for interactive prompts
"""

import importlib
import inspect
import argparse
import pkgutil
import json
import logging
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Callable
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ParameterInfo:
    """Information about a module parameter"""
    name: str  # The dest name used for storing the value (e.g., 'url', 'campaign')
    type: str
    required: bool
    default: Any
    help_text: str
    choices: Optional[List[str]] = None
    sensitive: bool = False
    action: Optional[str] = None  # argparse action: store_true, store_false, store_const, etc.
    cli_flags: Optional[List[str]] = None  # All CLI flag aliases (e.g., ['-u', '--url'])


@dataclass
class ModuleSchema:
    """Complete schema for a module"""
    module_name: str
    display_name: str
    description: str
    category: str
    parameters: List[ParameterInfo]
    execution_type: str  # 'argparse', 'class', 'subprocess'
    entrypoint: str


class ArgparseRecorder:
    """Monkeypatch argparse to record add_argument calls"""
    
    def __init__(self):
        self.parameters = []
        self.original_add_argument = None  # type: ignore  # Stores original argparse.add_argument method
    
    def record_add_argument(self, *args, **kwargs):
        """Record argparse add_argument calls"""
        # Extract CLI flags and dest
        cli_flags = [arg for arg in args if isinstance(arg, str) and arg.startswith('-')]
        
        # Determine dest: explicit dest kwarg > longest --flag > first flag stripped
        if 'dest' in kwargs:
            param_name = kwargs['dest']
        elif cli_flags:
            # Prefer longest --flag (e.g., --url over -u)
            long_flags = [f for f in cli_flags if f.startswith('--')]
            if long_flags:
                param_name = long_flags[0].lstrip('-').replace('-', '_')
            else:
                param_name = cli_flags[0].lstrip('-').replace('-', '_')
        else:
            param_name = 'unknown'
        
        # Detect boolean flags (store_true, store_false actions)
        action = kwargs.get('action', '')
        is_bool_flag = action in ('store_true', 'store_false', 'store_const')
        
        if is_bool_flag:
            param_type = 'bool'
            default_value = False if action == 'store_true' else (True if action == 'store_false' else kwargs.get('default'))
            required = False  # Boolean flags are never required
        else:
            param_type = kwargs.get('type', 'str').__name__ if callable(kwargs.get('type')) else 'str'
            default_value = kwargs.get('default')
            required = kwargs.get('required', False)
        
        param_info = ParameterInfo(
            name=param_name,
            type=param_type,
            required=required,
            default=default_value,
            help_text=kwargs.get('help', ''),
            choices=kwargs.get('choices'),
            sensitive='password' in param_name.lower() or 'secret' in param_name.lower() or 'key' in param_name.lower(),
            action=action if action else None,
            cli_flags=cli_flags if cli_flags else None
        )
        
        self.parameters.append(param_info)


class ModuleRegistry:
    """Registry for all Cerberus Agents modules"""
    
    def __init__(self, cache_path: str = '.module_cache.json'):
        self.cache_path = Path(cache_path)
        self.modules: Dict[str, ModuleSchema] = {}
        self.categories = {
            'reconnaissance': 'Reconnaissance & OSINT',
            'network': 'Network & Infrastructure',
            'wireless': 'Wireless Security',
            'web': 'Web Application Security',
            'database': 'Database Security',
            'ad': 'Active Directory & Windows',
            'cloud': 'Cloud Security',
            'container': 'Container & Kubernetes',
            'mobile': 'Mobile Security',
            'password': 'Password & Credential Attacks',
            'c2': 'Post-Exploitation & C2',
            'social': 'Social Engineering',
            'adversary': 'Adversary Simulation',
            'automotive': 'Automotive Security',
            'reversing': 'Reverse Engineering',
            'ai': 'AI/LLM Red Teaming',
            'utility': 'Utilities & Automation'
        }
    
    def discover_modules(self) -> None:
        """Discover all modules in cerberus_agents package"""
        logger.info("Discovering Cerberus Agents modules...")
        
        import cerberus_agents
        package_path = Path(cerberus_agents.__file__).parent
        
        for _, module_name, _ in pkgutil.iter_modules([str(package_path)]):
            if module_name.startswith('__'):
                continue
            
            try:
                schema = self._introspect_module(module_name)
                if schema:
                    self.modules[module_name] = schema
                    logger.info(f"✓ Registered: {module_name}")
            except Exception as e:
                logger.warning(f"⚠ Failed to introspect {module_name}: {e}")
        
        logger.info(f"Discovered {len(self.modules)} modules")
    
    def _introspect_module(self, module_name: str) -> Optional[ModuleSchema]:
        """Introspect a module to extract its schema"""
        try:
            module = importlib.import_module(f'cerberus_agents.{module_name}')
        except Exception as e:
            logger.debug(f"Could not import {module_name}: {e}")
            return None
        
        # Try explicit metadata first
        if hasattr(module, '__module_schema__'):
            return module.__module_schema__
        
        # Try argparse introspection
        parameters = self._extract_argparse_params(module)
        
        # Fall back to class constructor introspection
        if not parameters:
            parameters = self._extract_class_params(module)
        
        # Determine category
        category = self._categorize_module(module_name)
        
        # Create schema
        display_name = module_name.replace('_', ' ').title()
        description = module.__doc__.split('\n')[0] if module.__doc__ else display_name
        
        return ModuleSchema(
            module_name=module_name,
            display_name=display_name,
            description=description,
            category=category,
            parameters=parameters,
            execution_type='argparse' if hasattr(module, 'main') else 'class',
            entrypoint='main' if hasattr(module, 'main') else 'run'
        )
    
    def _extract_argparse_params(self, module) -> List[ParameterInfo]:
        """Extract parameters from argparse definition"""
        parameters = []
        
        # First try looking for build_parser or create_parser functions (legacy support)
        for func_name in ['build_parser', 'create_parser', 'get_parser']:
            if hasattr(module, func_name):
                recorder = ArgparseRecorder()
                original_add = argparse.ArgumentParser.add_argument
                
                try:
                    # Monkeypatch ArgumentParser
                    def patched_add(self, *args, **kwargs):
                        recorder.record_add_argument(*args, **kwargs)
                        return original_add(self, *args, **kwargs)
                    
                    argparse.ArgumentParser.add_argument = patched_add
                    
                    # Call parser builder
                    getattr(module, func_name)()
                    
                    parameters = recorder.parameters
                    break
                except Exception as e:
                    logger.debug(f"Argparse extraction failed: {e}")
                finally:
                    # CRITICAL: Always restore original, even on exceptions
                    argparse.ArgumentParser.add_argument = original_add
        
        # If no parser builder found, try to extract from main() function
        if not parameters and hasattr(module, 'main'):
            import sys
            recorder = ArgparseRecorder()
            
            # Save original methods
            original_add = argparse.ArgumentParser.add_argument
            original_parse_args = argparse.ArgumentParser.parse_args
            old_argv = sys.argv
            
            # Custom exception to signal successful parameter extraction
            class ParameterExtractionComplete(Exception):
                pass
            
            try:
                # Monkeypatch ArgumentParser to record arguments
                def patched_add(self, *args, **kwargs):
                    recorder.record_add_argument(*args, **kwargs)
                    return original_add(self, *args, **kwargs)
                
                # Patch parse_args to exit early with a dummy namespace
                def patched_parse_args(self, args=None, namespace=None):
                    # Create a minimal dummy namespace to avoid breaking modules
                    # that expect parse_args() to return a namespace
                    dummy_ns = argparse.Namespace()
                    # Raise our custom exception to signal we're done
                    raise ParameterExtractionComplete()
                
                argparse.ArgumentParser.add_argument = patched_add
                argparse.ArgumentParser.parse_args = patched_parse_args
                
                # Call main() - it will exit at parse_args() but we'll have recorded all arguments
                sys.argv = [module.__name__]  # Provide minimal argv to prevent errors
                try:
                    import inspect
                    main_func = module.main
                    if inspect.iscoroutinefunction(main_func):
                        # For async main(), call it with asyncio to avoid "coroutine never awaited" warnings
                        import asyncio
                        try:
                            asyncio.run(main_func())
                        except RuntimeError:
                            # If event loop already running, skip
                            pass
                    else:
                        main_func()
                except (SystemExit, ParameterExtractionComplete):
                    # Expected - parse_args() causes exit or raises our exception
                    pass
                
                parameters = recorder.parameters
                logger.debug(f"Extracted {len(parameters)} parameters from main() for {module.__name__}")
                
            except Exception as e:
                logger.warning(f"Main() argparse extraction failed for {module.__name__}: {type(e).__name__}: {e}")
            finally:
                # CRITICAL: Always restore original methods and argv, even on exceptions
                argparse.ArgumentParser.add_argument = original_add
                argparse.ArgumentParser.parse_args = original_parse_args
                sys.argv = old_argv
        
        return parameters
    
    def _extract_class_params(self, module) -> List[ParameterInfo]:
        """Extract parameters from class constructor"""
        parameters = []
        
        # Find primary class (usually matches module name or contains "Scanner", "Agent", etc.)
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if obj.__module__ == module.__name__:
                try:
                    sig = inspect.signature(obj.__init__)
                    for param_name, param in sig.parameters.items():
                        if param_name in ['self', 'args', 'kwargs']:
                            continue
                        
                        param_info = ParameterInfo(
                            name=param_name,
                            type=param.annotation.__name__ if param.annotation != inspect.Parameter.empty else 'str',
                            required=param.default == inspect.Parameter.empty,
                            default=param.default if param.default != inspect.Parameter.empty else None,
                            help_text=f"Parameter: {param_name}",
                            sensitive='password' in param_name.lower() or 'secret' in param_name.lower()
                        )
                        parameters.append(param_info)
                    
                    if parameters:
                        break
                except Exception as e:
                    logger.debug(f"Class param extraction failed: {e}")
        
        return parameters
    
    def _categorize_module(self, module_name: str) -> str:
        """Determine module category based on name"""
        name_lower = module_name.lower()
        
        if any(x in name_lower for x in ['osint', 'recon', 'subdomain', 'cctv', 'facial', 'phone', 'email', 'spiderfoot', 'theharvester', 'metagoofil']):
            return 'reconnaissance'
        elif any(x in name_lower for x in ['network', 'scanner', 'nmap', 'rustscan', 'naabu', 'port', 'pivoting', 'ligolo', 'chisel']):
            return 'network'
        elif any(x in name_lower for x in ['wireless', 'wifi', 'wpa', 'aircrack', 'wifite', 'bettercap', 'pineapple', 'airgeddon']):
            return 'wireless'
        elif any(x in name_lower for x in ['web', 'http', 'api', 'ssl', 'tls', 'ffuf', 'feroxbuster', 'katana', 'httpx', 'zap', 'wapiti', 'sqlmap']):
            return 'web'
        elif any(x in name_lower for x in ['database', 'sql', 'nosql', 'mongo', 'mysql', 'postgres']):
            return 'database'
        elif any(x in name_lower for x in ['ad', 'active_directory', 'kerberos', 'ldap', 'bloodhound', 'impacket', 'winrm', 'lsassy', 'donpapi', 'certipy', 'netexec', 'kerbrute', 'enum4linux']):
            return 'ad'
        elif any(x in name_lower for x in ['cloud', 'aws', 'azure', 'gcp', 'pacu', 'prowler', 'cloudfox', 'scoutsuite', 'roadtools', 'aadinternals', 'graphrunner', 'microburst']):
            return 'cloud'
        elif any(x in name_lower for x in ['container', 'kubernetes', 'k8s', 'docker', 'trivy', 'kube', 'kubelet', 'peirates', 'cdk', 'deepce']):
            return 'container'
        elif any(x in name_lower for x in ['mobile', 'ios', 'android', 'apk', 'frida', 'objection', 'mobsf', 'macos']):
            return 'mobile'
        elif any(x in name_lower for x in ['password', 'hash', 'crack', 'credential', 'hydra', 'hashcat']):
            return 'password'
        elif any(x in name_lower for x in ['c2', 'sliver', 'mythic', 'empire', 'covenant', 'havoc', 'merlin', 'poshc2', 'rclone', 'dns_tunnel', 'ghostpack', 'exfil']):
            return 'c2'
        elif any(x in name_lower for x in ['social', 'phishing', 'gophish', 'evilginx']):
            return 'social'
        elif any(x in name_lower for x in ['adversary', 'caldera', 'atomic', 'detection']):
            return 'adversary'
        elif any(x in name_lower for x in ['vehicle', 'automotive', 'can', 'ecu', 'ota', 'telematics']):
            return 'automotive'
        elif any(x in name_lower for x in ['ghidra', 'exploit', 'fuzzing', 'mangle', 'alcatraz', 'sharpshooter']):
            return 'reversing'
        elif any(x in name_lower for x in ['garak', 'ai', 'llm']):
            return 'ai'
        else:
            return 'utility'
    
    def save_cache(self) -> None:
        """Save module schemas to cache"""
        cache_data = {name: asdict(schema) for name, schema in self.modules.items()}
        with open(self.cache_path, 'w') as f:
            json.dump(cache_data, f, indent=2, default=str)
        logger.info(f"Saved {len(self.modules)} module schemas to cache")
    
    def load_cache(self) -> bool:
        """Load module schemas from cache"""
        if not self.cache_path.exists():
            return False
        
        try:
            with open(self.cache_path, 'r') as f:
                cache_data = json.load(f)
            
            for name, data in cache_data.items():
                # Reconstruct objects from dict
                data['parameters'] = [ParameterInfo(**p) for p in data['parameters']]
                self.modules[name] = ModuleSchema(**data)
            
            logger.info(f"Loaded {len(self.modules)} module schemas from cache")
            return True
        except Exception as e:
            logger.warning(f"Failed to load cache: {e}")
            return False
    
    def get_module(self, module_name: str) -> Optional[ModuleSchema]:
        """Get module schema by name"""
        return self.modules.get(module_name)
    
    def get_modules_by_category(self, category: str) -> List[ModuleSchema]:
        """Get all modules in a category"""
        return [m for m in self.modules.values() if m.category == category]
    
    def rebuild_cache(self) -> None:
        """Force rebuild of module cache"""
        logger.info("Rebuilding module cache...")
        self.modules.clear()
        self.discover_modules()
        self.save_cache()


if __name__ == "__main__":
    # Test the registry
    registry = ModuleRegistry()
    
    if not registry.load_cache():
        registry.discover_modules()
        registry.save_cache()
    
    print(f"\n✅ Registered {len(registry.modules)} modules")
    
    # Show some examples
    for category, modules in registry.categories.items():
        cat_modules = registry.get_modules_by_category(category)
        if cat_modules:
            print(f"\n{modules}: {len(cat_modules)} modules")
