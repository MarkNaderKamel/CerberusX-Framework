#!/usr/bin/env python3
"""
Atomic Red Team - MITRE ATT&CK Testing Framework
Automated execution of atomic tests mapped to MITRE ATT&CK techniques
Production-ready adversary emulation for testing detection capabilities
"""

import subprocess
import json
import logging
import argparse
import os
import sys
import yaml
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class AtomicRedTeam:
    """
    Atomic Red Team integration for MITRE ATT&CK technique execution
    Tests blue team detection capabilities with real adversary tactics
    """
    
    def __init__(self, atomics_path: Optional[str] = None):
        self.atomics_path = atomics_path or str(Path.home() / "AtomicRedTeam/atomics")
        self.results = []
        
    def check_installation(self) -> bool:
        """Check if Invoke-AtomicRedTeam is installed"""
        if sys.platform == 'win32':
            # PowerShell check
            try:
                result = subprocess.run(
                    ['powershell', '-Command', 'Get-Module -ListAvailable -Name invoke-atomicredteam'],
                    capture_output=True, text=True, timeout=10
                )
                if 'invoke-atomicredteam' in result.stdout.lower():
                    logger.info("Invoke-AtomicRedTeam is installed")
                    return True
            except Exception as e:
                logger.debug(f"PowerShell check failed: {e}")
        
        # Check for atomics directory
        if os.path.exists(self.atomics_path):
            logger.info(f"Atomics found at: {self.atomics_path}")
            return True
        
        logger.error("Atomic Red Team not installed")
        return False
    
    def clone_atomics(self) -> bool:
        """Clone Atomic Red Team repository"""
        atomics_dir = Path.home() / "AtomicRedTeam"
        
        if atomics_dir.exists():
            logger.info("Atomics already cloned, updating...")
            try:
                subprocess.run(['git', 'pull'], cwd=atomics_dir, 
                             capture_output=True, timeout=60)
                return True
            except Exception as e:
                logger.error(f"Error updating atomics: {e}")
                return False
        
        logger.info("Cloning Atomic Red Team repository...")
        try:
            subprocess.run([
                'git', 'clone',
                'https://github.com/redcanaryco/atomic-red-team.git',
                str(atomics_dir)
            ], capture_output=True, timeout=300)
            
            self.atomics_path = str(atomics_dir / "atomics")
            logger.info(f"Atomics cloned to: {self.atomics_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error cloning atomics: {e}")
            return False
    
    def list_techniques(self, tactic: Optional[str] = None) -> List[Dict]:
        """
        List available ATT&CK techniques
        
        Args:
            tactic: Filter by MITRE ATT&CK tactic (e.g., 'execution', 'persistence')
        """
        if not os.path.exists(self.atomics_path):
            logger.error(f"Atomics path not found: {self.atomics_path}")
            return []
        
        techniques = []
        
        for technique_dir in Path(self.atomics_path).iterdir():
            if technique_dir.is_dir() and technique_dir.name.startswith('T'):
                yaml_file = technique_dir / f"{technique_dir.name}.yaml"
                
                if yaml_file.exists():
                    try:
                        with open(yaml_file, 'r') as f:
                            data = yaml.safe_load(f)
                            
                            technique_info = {
                                'technique_id': technique_dir.name,
                                'name': data.get('display_name', 'Unknown'),
                                'tactics': data.get('attack_technique', {}).get('tactic', []),
                                'tests_count': len(data.get('atomic_tests', []))
                            }
                            
                            if tactic:
                                if tactic.lower() in [t.lower() for t in technique_info['tactics']]:
                                    techniques.append(technique_info)
                            else:
                                techniques.append(technique_info)
                                
                    except Exception as e:
                        logger.debug(f"Error parsing {yaml_file}: {e}")
        
        return sorted(techniques, key=lambda x: x['technique_id'])
    
    def get_technique_details(self, technique_id: str) -> Dict:
        """Get detailed information about a technique"""
        yaml_file = Path(self.atomics_path) / technique_id / f"{technique_id}.yaml"
        
        if not yaml_file.exists():
            return {"error": f"Technique {technique_id} not found"}
        
        try:
            with open(yaml_file, 'r') as f:
                data = yaml.safe_load(f)
                
                return {
                    'technique_id': technique_id,
                    'name': data.get('display_name', 'Unknown'),
                    'description': data.get('attack_technique', {}).get('description', ''),
                    'tactics': data.get('attack_technique', {}).get('tactic', []),
                    'platforms': data.get('attack_technique', {}).get('platform', []),
                    'tests': [
                        {
                            'name': test.get('name', ''),
                            'description': test.get('description', ''),
                            'platforms': test.get('supported_platforms', []),
                            'executor': test.get('executor', {}).get('name', '')
                        }
                        for test in data.get('atomic_tests', [])
                    ]
                }
                
        except Exception as e:
            logger.error(f"Error reading technique details: {e}")
            return {"error": str(e)}
    
    def execute_test(self, technique_id: str, test_number: Optional[int] = None,
                    cleanup: bool = False) -> Dict:
        """
        Execute atomic test (Windows PowerShell only)
        
        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., T1003.001)
            test_number: Specific test number to run (runs all if None)
            cleanup: Run cleanup commands after execution
        """
        if sys.platform != 'win32':
            logger.warning("Test execution requires Windows with PowerShell")
            return self._simulate_linux_test(technique_id, test_number)
        
        cmd = [
            'powershell', '-ExecutionPolicy', 'Bypass', '-Command',
            f'Invoke-AtomicTest {technique_id}'
        ]
        
        if test_number is not None:
            cmd[-1] += f' -TestNumbers {test_number}'
        
        if cleanup:
            cmd[-1] += ' -Cleanup'
        
        logger.info(f"Executing atomic test: {technique_id}")
        logger.warning("⚠️  This will execute real attack techniques on this system!")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            return {
                'technique_id': technique_id,
                'test_number': test_number,
                'status': 'success' if result.returncode == 0 else 'failed',
                'output': result.stdout,
                'errors': result.stderr
            }
            
        except subprocess.TimeoutExpired:
            logger.error("Test execution timeout")
            return {'error': 'Timeout'}
        except Exception as e:
            logger.error(f"Execution error: {e}")
            return {'error': str(e)}
    
    def _simulate_linux_test(self, technique_id: str, test_number: Optional[int] = None) -> Dict:
        """
        Execute Linux-compatible atomic tests
        """
        details = self.get_technique_details(technique_id)
        
        if 'error' in details:
            return details
        
        tests = details.get('tests', [])
        
        if test_number is not None:
            if test_number > len(tests):
                return {"error": f"Test {test_number} not found"}
            tests = [tests[test_number - 1]]
        
        linux_tests = [t for t in tests if 'linux' in [p.lower() for p in t['platforms']]]
        
        if not linux_tests:
            return {
                "technique_id": technique_id,
                "status": "skipped",
                "reason": "No Linux-compatible tests available",
                "available_platforms": list(set([p for t in tests for p in t['platforms']]))
            }
        
        logger.info(f"Found {len(linux_tests)} Linux-compatible test(s)")
        
        # Parse and execute bash commands from test definitions
        yaml_file = Path(self.atomics_path) / technique_id / f"{technique_id}.yaml"
        
        with open(yaml_file, 'r') as f:
            data = yaml.safe_load(f)
        
        results = []
        for i, test in enumerate(data.get('atomic_tests', [])):
            if 'linux' not in [p.lower() for p in test.get('supported_platforms', [])]:
                continue
            
            if test.get('executor', {}).get('name') in ['bash', 'sh']:
                command = test.get('executor', {}).get('command', '')
                
                if command:
                    logger.info(f"Executing test {i+1}: {test.get('name')}")
                    logger.warning(f"Command: {command[:100]}...")
                    
                    try:
                        result = subprocess.run(
                            command,
                            shell=True,
                            capture_output=True,
                            text=True,
                            timeout=60
                        )
                        
                        results.append({
                            'test_name': test.get('name'),
                            'status': 'completed',
                            'return_code': result.returncode,
                            'output': result.stdout[:500]
                        })
                        
                    except Exception as e:
                        results.append({
                            'test_name': test.get('name'),
                            'status': 'error',
                            'error': str(e)
                        })
        
        return {
            'technique_id': technique_id,
            'platform': 'linux',
            'tests_executed': len(results),
            'results': results
        }
    
    def generate_test_plan(self, tactics: List[str], output_file: str) -> Dict:
        """
        Generate test plan for specific tactics
        
        Args:
            tactics: List of MITRE tactics (e.g., ['execution', 'persistence'])
            output_file: Path to save test plan
        """
        test_plan = {
            'name': f'Atomic Red Team Test Plan - {datetime.now().strftime("%Y-%m-%d")}',
            'tactics': tactics,
            'techniques': []
        }
        
        for tactic in tactics:
            techniques = self.list_techniques(tactic=tactic)
            for tech in techniques[:5]:  # Top 5 per tactic
                details = self.get_technique_details(tech['technique_id'])
                test_plan['techniques'].append({
                    'technique_id': tech['technique_id'],
                    'name': tech['name'],
                    'tactic': tactic,
                    'tests': details.get('tests', [])
                })
        
        with open(output_file, 'w') as f:
            yaml.dump(test_plan, f, default_flow_style=False)
        
        logger.info(f"Test plan saved to: {output_file}")
        
        return test_plan
    
    def generate_report(self, results: List[Dict], output_file: str):
        """Generate execution report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_tests': len(results),
            'successful': len([r for r in results if r.get('status') == 'success']),
            'failed': len([r for r in results if r.get('status') == 'failed']),
            'results': results
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Atomic Red Team - MITRE ATT&CK Testing")
    parser.add_argument('--clone', action='store_true', help='Clone/update Atomics repository')
    parser.add_argument('--list', action='store_true', help='List available techniques')
    parser.add_argument('--tactic', help='Filter by tactic (execution, persistence, etc.)')
    parser.add_argument('--technique', help='Get details or execute technique (e.g., T1003.001)')
    parser.add_argument('--execute', action='store_true', help='Execute the technique')
    parser.add_argument('--test-number', type=int, help='Specific test number to execute')
    parser.add_argument('--cleanup', action='store_true', help='Run cleanup after execution')
    parser.add_argument('--generate-plan', nargs='+', help='Generate test plan for tactics')
    parser.add_argument('--output', help='Output file for plan/report')
    parser.add_argument('--authorized', action='store_true',
                       help='Confirm you have authorization to perform this action')
    args = parser.parse_args()
    
    art = AtomicRedTeam()
    
    if args.clone:
        art.clone_atomics()
        return
    
    if not art.check_installation():
        print("\n❌ Atomic Red Team not installed")
        print("\n📥 Installation Instructions:")
        print("   1. Clone repository:")
        print("      git clone https://github.com/redcanaryco/atomic-red-team.git ~/AtomicRedTeam")
        print("\n   2. Windows PowerShell:")
        print("      IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);")
        print("      Install-AtomicRedTeam -getAtomics")
        print("\n   3. Linux/macOS:")
        print("      Use --clone to download atomics")
        return
    
    if args.list:
        techniques = art.list_techniques(tactic=args.tactic)
        print(f"\n{'='*80}")
        print(f"ATOMIC RED TEAM TECHNIQUES")
        if args.tactic:
            print(f"Tactic: {args.tactic}")
        print(f"{'='*80}\n")
        
        for tech in techniques:
            print(f"{tech['technique_id']}: {tech['name']}")
            print(f"  Tactics: {', '.join(tech['tactics'])}")
            print(f"  Tests: {tech['tests_count']}\n")
        
        print(f"Total: {len(techniques)} techniques")
        return
    
    if args.technique:
        details = art.get_technique_details(args.technique)
        
        if 'error' in details:
            print(f"Error: {details['error']}")
            return
        
        print(f"\n{'='*80}")
        print(f"{details['technique_id']}: {details['name']}")
        print(f"{'='*80}")
        print(f"\nTactics: {', '.join(details['tactics'])}")
        print(f"Platforms: {', '.join(details['platforms'])}")
        print(f"\nDescription:\n{details['description']}")
        print(f"\n{'='*80}")
        print(f"ATOMIC TESTS ({len(details['tests'])} available)")
        print(f"{'='*80}\n")
        
        for i, test in enumerate(details['tests'], 1):
            print(f"{i}. {test['name']}")
            print(f"   Platforms: {', '.join(test['platforms'])}")
            print(f"   Executor: {test['executor']}")
            print(f"   {test['description']}\n")
        
        if args.execute:
            print("\n⚠️  WARNING: This will execute real attack techniques!")
            print("⚠️  Ensure you have authorization and are in a test environment.")
            
            response = input("\nContinue? (yes/no): ")
            if response.lower() != 'yes':
                print("Execution cancelled")
                return
            
            result = art.execute_test(args.technique, args.test_number, args.cleanup)
            print(json.dumps(result, indent=2))
    
    if args.generate_plan:
        output_file = args.output or 'atomic_test_plan.yaml'
        plan = art.generate_test_plan(args.generate_plan, output_file)
        print(f"Test plan generated: {output_file}")
        print(f"Techniques: {len(plan['techniques'])}")


if __name__ == "__main__":
    main()
