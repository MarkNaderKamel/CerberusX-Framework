#!/usr/bin/env python3
"""
Test script to verify the parameter extraction and execution fixes
"""

import json
from cerberus_agents.module_registry import ModuleRegistry
from cerberus_agents.execution_adapter import ExecutionAdapter

def test_sqlmap_module():
    """Test SQLMap module with correct parameters"""
    print("=" * 70)
    print("TEST 1: SQLMap Exploitation Module")
    print("=" * 70)
    
    # Load registry
    registry = ModuleRegistry()
    registry.load_cache()
    
    # Get SQLMap schema
    schema = registry.get_module('sqlmap_exploitation')
    if not schema:
        print("❌ FAILED: Could not load sqlmap_exploitation schema")
        return False
    
    # Check parameters
    print(f"\n✅ Schema loaded with {len(schema.parameters)} parameters:")
    for p in schema.parameters:
        if p.name in ['url', 'campaign']:
            print(f"  - {p.name}: {p.cli_flags} (required={p.required})")
    
    # Check that url parameter exists and is required
    url_param = next((p for p in schema.parameters if p.name == 'url'), None)
    if not url_param:
        print("\n❌ FAILED: No 'url' parameter found!")
        return False
    
    if not url_param.required:
        print("\n❌ FAILED: 'url' parameter is not marked as required!")
        return False
    
    if not url_param.cli_flags or '--url' not in url_param.cli_flags:
        print(f"\n❌ FAILED: 'url' parameter has wrong cli_flags: {url_param.cli_flags}")
        return False
    
    print("\n✅ SUCCESS: SQLMap module has correct parameters!")
    
    # Test parameter to CLI conversion
    adapter = ExecutionAdapter()
    test_params = {
        'url': 'http://example.com/test?id=1',
        'method': 'GET',
        'authorized': True
    }
    
    # Dry run - just build the args
    args = []
    for param_name, param_value in test_params.items():
        param_info = next((p for p in schema.parameters if p.name == param_name), None)
        if not param_info:
            continue
        
        if param_info.cli_flags:
            long_flags = [f for f in param_info.cli_flags if f.startswith('--')]
            arg_name = long_flags[0] if long_flags else param_info.cli_flags[0]
        else:
            arg_name = f"--{param_name.replace('_', '-')}"
        
        if param_info.action == 'store_true' and param_value:
            args.append(arg_name)
        elif not isinstance(param_value, bool):
            args.append(arg_name)
            args.append(str(param_value))
    
    print(f"\n✅ Command would be: python -m cerberus_agents.sqlmap_exploitation {' '.join(args)}")
    
    if '--url' not in args:
        print("\n❌ FAILED: --url not in generated arguments!")
        return False
    
    return True


def test_social_engineering_module():
    """Test Social Engineering module with correct parameters"""
    print("\n" + "=" * 70)
    print("TEST 2: Social Engineering Module")
    print("=" * 70)
    
    # Load registry
    registry = ModuleRegistry()
    registry.load_cache()
    
    # Get social engineering schema
    schema = registry.get_module('social_engineering')
    if not schema:
        print("❌ FAILED: Could not load social_engineering schema")
        return False
    
    # Check parameters
    print(f"\n✅ Schema loaded with {len(schema.parameters)} parameters:")
    for p in schema.parameters:
        if p.name in ['campaign', 'campaign_name']:
            print(f"  - {p.name}: {p.cli_flags} (required={p.required})")
    
    # Check that campaign parameter exists (not campaign_name from class constructor)
    campaign_param = next((p for p in schema.parameters if p.name == 'campaign'), None)
    if not campaign_param:
        print("\n❌ FAILED: No 'campaign' parameter found!")
        print("   (This suggests extraction fell back to class constructor)")
        return False
    
    if not campaign_param.required:
        print("\n❌ FAILED: 'campaign' parameter is not marked as required!")
        return False
    
    if not campaign_param.cli_flags or '--campaign' not in campaign_param.cli_flags:
        print(f"\n❌ FAILED: 'campaign' parameter has wrong cli_flags: {campaign_param.cli_flags}")
        return False
    
    # Make sure campaign_name (from class) is NOT present
    campaign_name_param = next((p for p in schema.parameters if p.name == 'campaign_name'), None)
    if campaign_name_param:
        print("\n❌ FAILED: 'campaign_name' parameter found (should be 'campaign' from argparse)!")
        return False
    
    print("\n✅ SUCCESS: Social Engineering module has correct parameters!")
    
    # Test parameter to CLI conversion
    test_params = {
        'campaign': 'Alhekma',
        'targets': 100,
        'authorized': True
    }
    
    args = []
    for param_name, param_value in test_params.items():
        param_info = next((p for p in schema.parameters if p.name == param_name), None)
        if not param_info:
            continue
        
        if param_info.cli_flags:
            long_flags = [f for f in param_info.cli_flags if f.startswith('--')]
            arg_name = long_flags[0] if long_flags else param_info.cli_flags[0]
        else:
            arg_name = f"--{param_name.replace('_', '-')}"
        
        if param_info.action == 'store_true' and param_value:
            args.append(arg_name)
        elif not isinstance(param_value, bool):
            args.append(arg_name)
            args.append(str(param_value))
    
    print(f"\n✅ Command would be: python -m cerberus_agents.social_engineering {' '.join(args)}")
    
    if '--campaign' not in args:
        print("\n❌ FAILED: --campaign not in generated arguments!")
        return False
    
    if '--campaign-name' in args:
        print("\n❌ FAILED: --campaign-name in generated arguments (should be --campaign)!")
        return False
    
    return True


if __name__ == "__main__":
    print("\n🧪 TESTING MODULE PARAMETER EXTRACTION FIXES\n")
    
    test1_passed = test_sqlmap_module()
    test2_passed = test_social_engineering_module()
    
    print("\n" + "=" * 70)
    print("TEST RESULTS")
    print("=" * 70)
    print(f"  SQLMap Module:           {'✅ PASS' if test1_passed else '❌ FAIL'}")
    print(f"  Social Engineering Module: {'✅ PASS' if test2_passed else '❌ FAIL'}")
    print("=" * 70)
    
    if test1_passed and test2_passed:
        print("\n✅ ALL TESTS PASSED! The fixes are working correctly.")
        exit(0)
    else:
        print("\n❌ SOME TESTS FAILED! There are still issues to fix.")
        exit(1)
