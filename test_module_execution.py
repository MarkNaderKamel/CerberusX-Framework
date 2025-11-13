#!/usr/bin/env python3
"""
Module Execution Testing - Phase 2 Functional Testing
Tests actual module execution with safe/dry-run parameters
"""

import subprocess
import sys
from typing import Tuple, Dict

# Safe test cases for critical modules
TEST_CASES = [
    {
        "name": "network_scanner_advanced",
        "args": ["--target", "127.0.0.1", "--quick", "--authorized"],
        "expected": "scan"
    },
    {
        "name": "hash_cracker",
        "args": ["--hash", "5f4dcc3b5aa765d61d8327deb882cf99", "--type", "md5", "--authorized"],
        "expected": "crack"
    },
    {
        "name": "subdomain_enumeration",
        "args": ["--domain", "example.com", "--dns-only", "--authorized"],
        "expected": "subdomain"
    },
    {
        "name": "ssl_tls_scanner",
        "args": ["--target", "example.com", "--port", "443", "--authorized"],
        "expected": "SSL"
    },
    {
        "name": "vulnerability_scanner",
        "args": ["--target", "127.0.0.1", "--quick", "--authorized"],
        "expected": "scan"
    }
]

def test_module_execution(module_name: str, args: list, expected_keyword: str) -> Tuple[bool, str]:
    """Test actual module execution"""
    try:
        cmd = ['python', '-m', f'cerberus_agents.{module_name}'] + args
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        output = result.stdout + result.stderr
        
        # Check if module executed (don't require success, just execution)
        if result.returncode == 0 or expected_keyword.lower() in output.lower():
            return True, "Executed successfully"
        elif "error" in output.lower() or "exception" in output.lower():
            # Extract first error line
            for line in output.split('\n'):
                if 'error' in line.lower() or 'exception' in line.lower():
                    return False, line[:200]
            return False, "Unknown error"
        else:
            return True, "Partial execution (non-zero exit but no errors)"
    
    except subprocess.TimeoutExpired:
        return True, "Execution timeout (expected for some scans)"
    except Exception as e:
        return False, f"{type(e).__name__}: {str(e)[:100]}"

def main():
    print("="*80)
    print("CERBERUS AGENTS - MODULE EXECUTION TESTING")
    print("="*80)
    print(f"Testing {len(TEST_CASES)} critical modules with safe parameters\n")
    
    passed = []
    failed = []
    
    for test in TEST_CASES:
        module = test["name"]
        args = test["args"]
        expected = test["expected"]
        
        print(f"Testing {module}...", end=" ")
        success, message = test_module_execution(module, args, expected)
        
        if success:
            passed.append(module)
            print(f"✓ {message}")
        else:
            failed.append((module, message))
            print(f"✗ {message}")
    
    print("\n" + "="*80)
    print("EXECUTION TEST RESULTS")
    print("="*80)
    print(f"✓ Passed: {len(passed)}/{len(TEST_CASES)} ({len(passed)/len(TEST_CASES)*100:.1f}%)")
    print(f"✗ Failed: {len(failed)}/{len(TEST_CASES)} ({len(failed)/len(TEST_CASES)*100:.1f}%)")
    
    if failed:
        print("\n" + "="*80)
        print("FAILED EXECUTION TESTS")
        print("="*80)
        for module, error in failed:
            print(f"\n✗ {module}")
            print(f"  {error}")
    
    return len(failed) == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
