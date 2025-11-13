#!/usr/bin/env python3
"""
Cerberus Agents v16.0 - FULLY INTERACTIVE PRODUCTION SECURITY TOOLKIT
Enterprise-grade penetration testing framework with automated parameter collection
ALL 128 modules are now fully interactive - select, answer prompts, and execute!
"""

import sys
import logging
from pathlib import Path
from cerberus_agents.module_registry import ModuleRegistry
from cerberus_agents.prompt_orchestrator import PromptOrchestrator
from cerberus_agents.execution_adapter import ExecutionAdapter

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def print_banner():
    """Display Cerberus Agents banner"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗███████╗██████╗ ██████╗ ███████╗██████╗ ██╗   ██╗ ║
║  ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██║   ██║ ║
║  ██║     █████╗  ██████╔╝██████╔╝█████╗  ██████╔╝██║   ██║ ║
║  ██║     ██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██╗██║   ██║ ║
║  ╚██████╗███████╗██║  ██║██████╔╝███████╗██║  ██║╚██████╔╝ ║
║   ╚═════╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝  ║
║                                                              ║
║   FULLY INTERACTIVE TOOLKIT v16.0 - 2025 EDITION            ║
║   128 Advanced Modules | Automated Parameter Collection     ║
║   Production-Ready | Real Integrations | Auto-Execute       ║
╚══════════════════════════════════════════════════════════════╝
"""
    print(banner)
    print("\n⚡ NEW IN V16.0: FULLY INTERACTIVE CLI")
    print("   • Select ANY module from the menu")
    print("   • Answer interactive prompts for parameters")
    print("   • Automated execution with real integrations")
    print("   • All 128 modules now interactive!")
    
    print("\n⚠️  AUTHORIZATION REQUIRED:")
    print("   • Only use with explicit written authorization")
    print("   • Unauthorized testing is illegal")
    print("   • Authorization confirmation required for each module\n")


def display_modules_by_category(registry: ModuleRegistry):
    """Display all modules organized by category"""
    print("\n" + "=" * 80)
    print("🔐 CERBERUS AGENTS - INTERACTIVE MODULE SELECTION")
    print("=" * 80)
    
    # Category icons
    category_icons = {
        'reconnaissance': '🔍',
        'network': '🌐',
        'wireless': '📡',
        'web': '🌍',
        'database': '💾',
        'ad': '🏢',
        'cloud': '☁️',
        'container': '🐳',
        'mobile': '📱',
        'password': '🔓',
        'c2': '🚀',
        'social': '🎭',
        'adversary': '⚔️',
        'automotive': '🚗',
        'reversing': '🔬',
        'ai': '🤖',
        'utility': '🛠️'
    }
    
    module_index = 1
    module_map = {}
    
    for category_key, category_name in registry.categories.items():
        modules = registry.get_modules_by_category(category_key)
        if not modules:
            continue
        
        icon = category_icons.get(category_key, '⚙️')
        print(f"\n┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
        print(f"┃  {icon} {category_name.upper():<66} ┃")
        print(f"┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
        
        for module in sorted(modules, key=lambda x: x.display_name):
            print(f"{module_index:3d}. {icon} {module.display_name}")
            module_map[str(module_index)] = module
            module_index += 1
    
    print(f"\n{'='*80}")
    print(f"Total Modules: {len(module_map)} | Type module number or 'q' to quit")
    print(f"{'='*80}")
    
    return module_map


def run_interactive_module(schema, orchestrator, adapter):
    """Run a module interactively"""
    try:
        # Collect parameters
        params = orchestrator.collect_parameters(schema)
        
        if not params.get('authorized', False):
            print("\n❌ Operation cancelled: Authorization not confirmed")
            return False
        
        # Display summary
        orchestrator.display_summary(params)
        
        # Confirm execution
        print(f"\n⚡ Ready to execute: {schema.display_name}")
        confirm = input("Proceed with execution? (yes/no): ").strip().lower()
        
        if confirm not in ['yes', 'y']:
            print("\n⏸️  Execution cancelled by user")
            return False
        
        # Execute module
        success = adapter.execute_module(schema, params)
        
        if success:
            print(f"\n{'='*70}")
            print("✅ MODULE EXECUTION COMPLETED SUCCESSFULLY")
            print(f"{'='*70}")
        else:
            print(f"\n{'='*70}")
            print("❌ MODULE EXECUTION FAILED")
            print(f"{'='*70}")
        
        return success
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation interrupted by user")
        return False
    except Exception as e:
        logger.error(f"❌ Error during module execution: {e}", exc_info=True)
        return False


def rebuild_cache(registry):
    """Rebuild module cache"""
    print("\n🔄 Rebuilding module cache...")
    print("This may take a minute as we discover all 128 modules...")
    registry.rebuild_cache()
    print("✅ Module cache rebuilt successfully!")


def show_module_details(schema):
    """Show detailed information about a module"""
    print(f"\n{'='*70}")
    print(f"📋 MODULE DETAILS: {schema.display_name}")
    print(f"{'='*70}")
    print(f"Category: {schema.category.title()}")
    print(f"Description: {schema.description}")
    print(f"Execution Type: {schema.execution_type}")
    print(f"\nParameters ({len(schema.parameters)} total):")
    
    if schema.parameters:
        for param in schema.parameters:
            req_str = "*REQUIRED*" if param.required else "optional"
            default_str = f" (default: {param.default})" if param.default is not None else ""
            print(f"  • {param.name} [{param.type}] - {req_str}{default_str}")
            if param.help_text:
                print(f"    {param.help_text}")
    else:
        print("  No parameters required")
    
    print(f"{'='*70}")


def main():
    """Main interactive CLI"""
    print_banner()
    
    # Initialize components
    registry = ModuleRegistry()
    orchestrator = PromptOrchestrator()
    adapter = ExecutionAdapter()
    
    # Load or build module cache
    print("🔍 Loading module registry...")
    if not registry.load_cache():
        print("⚠️  Module cache not found. Building for the first time...")
        print("This will take a moment...")
        registry.discover_modules()
        registry.save_cache()
    
    print(f"✅ Loaded {len(registry.modules)} modules\n")
    
    while True:
        try:
            # Display menu
            module_map = display_modules_by_category(registry)
            
            # Get user choice
            choice = input("\n🎯 Enter module number (or 'q' to quit, 'r' to rebuild cache): ").strip().lower()
            
            if choice in ['q', 'quit', 'exit', '0']:
                print("\n✅ Exiting Cerberus Agents. Stay secure! 🔐\n")
                break
            
            if choice in ['r', 'rebuild']:
                rebuild_cache(registry)
                continue
            
            if choice not in module_map:
                print("\n❌ Invalid module number. Please try again.")
                input("\nPress Enter to continue...")
                continue
            
            # Get selected module
            selected_module = module_map[choice]
            
            # Show module details
            show_module_details(selected_module)
            
            # Ask if user wants to proceed
            proceed = input("\n▶️  Run this module? (yes/no/details): ").strip().lower()
            
            if proceed == 'details':
                input("\nPress Enter to continue...")
                continue
            elif proceed not in ['yes', 'y']:
                print("\n⏸️  Module execution skipped")
                input("\nPress Enter to continue...")
                continue
            
            # Run the module interactively
            run_interactive_module(selected_module, orchestrator, adapter)
            
            # Pause before returning to menu
            input("\n\nPress Enter to return to main menu...")
            
        except KeyboardInterrupt:
            print("\n\n⚠️  Interrupted by user")
            confirm_exit = input("Exit Cerberus Agents? (yes/no): ").strip().lower()
            if confirm_exit in ['yes', 'y']:
                print("\n✅ Goodbye! 🔐\n")
                break
        except Exception as e:
            logger.error(f"❌ Unexpected error: {e}", exc_info=True)
            input("\nPress Enter to continue...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n✅ Interrupted by user. Goodbye! 🔐\n")
        sys.exit(0)
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}", exc_info=True)
        sys.exit(1)
