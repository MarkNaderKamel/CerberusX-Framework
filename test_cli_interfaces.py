#!/usr/bin/env python3
"""
CLI Interface Testing - Phase 2
Tests CLI argument parsing and help for all modules
"""

import sys
import subprocess
from typing import Tuple, List

# Priority Tier 0 - Core Platform Modules
TIER_0_MODULES = [
    "module_registry",
    "prompt_orchestrator",
    "execution_adapter"
]

# Priority Tier 1 - Mission Critical
TIER_1_MODULES = [
    "network_scanner_advanced",
    "subdomain_enumeration",
    "osint_reconnaissance",
    "impacket_lateral_movement",
    "bloodhound_analyzer",
    "kerberos_attacks",
    "aws_exploitation",
    "container_kubernetes_security",
    "hash_cracker",
    "credential_dumping",
    "c2_integration"
]

# Priority Tier 2 - Secondary
TIER_2_MODULES = [
    "vulnerability_scanner",
    "web_vuln_scanner",
    "ssl_tls_scanner",
    "wireless_security",
    "android_pentesting_suite",
    "ios_pentesting_framework",
    "social_engineering",
    "payload_generator",
    "exploit_development"
]

def test_module_cli(module_name: str) -> Tuple[bool, str]:
    """Test if module has working CLI interface"""
    try:
        result = subprocess.run(
            ['python', '-m', f'cerberus_agents.{module_name}', '--help'],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0 and ('usage:' in result.stdout.lower() or 'help' in result.stdout.lower()):
            return True, "CLI OK"
        else:
            return False, f"No CLI interface or error: {result.stderr[:100]}"
    
    except subprocess.TimeoutExpired:
        return False, "CLI timeout"
    except Exception as e:
        return False, f"Error: {type(e).__name__}: {str(e)[:100]}"

def test_tier(tier_name: str, modules: List[str]):
    """Test a tier of modules"""
    print(f"\n{'='*80}")
    print(f"{tier_name}")
    print(f"{'='*80}")
    
    passed = []
    failed = []
    
    for module in modules:
        success, message = test_module_cli(module)
        if success:
            passed.append(module)
            print(f"✓ {module}")
        else:
            failed.append((module, message))
            print(f"✗ {module}: {message}")
    
    print(f"\n{tier_name} Results: {len(passed)}/{len(modules)} passed")
    return passed, failed

def main():
    print("="*80)
    print("CERBERUS AGENTS - CLI INTERFACE TESTING")
    print("="*80)
    
    all_passed = []
    all_failed = []
    
    # Test Tier 0
    passed, failed = test_tier("TIER 0: Core Platform Modules", TIER_0_MODULES)
    all_passed.extend(passed)
    all_failed.extend(failed)
    
    # Test Tier 1
    passed, failed = test_tier("TIER 1: Mission Critical Modules", TIER_1_MODULES)
    all_passed.extend(passed)
    all_failed.extend(failed)
    
    # Test Tier 2
    passed, failed = test_tier("TIER 2: Secondary Modules", TIER_2_MODULES)
    all_passed.extend(passed)
    all_failed.extend(failed)
    
    print("\n" + "="*80)
    print("OVERALL CLI TEST RESULTS")
    print("="*80)
    total = len(all_passed) + len(all_failed)
    print(f"✓ Passed: {len(all_passed)}/{total} ({len(all_passed)/total*100:.1f}%)")
    print(f"✗ Failed: {len(all_failed)}/{total} ({len(all_failed)/total*100:.1f}%)")
    
    if all_failed:
        print("\n" + "="*80)
        print("FAILED CLI TESTS")
        print("="*80)
        for module, error in all_failed:
            print(f"\n✗ {module}")
            print(f"  {error}")
    
    return len(all_failed) == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
