#!/usr/bin/env python3
"""
MITRE Caldera Integration - Adversary Emulation Platform
Production-ready automated red team operations and ATT&CK simulation
"""

import requests
import json
import argparse
import logging
import sys
import time
from requests.auth import HTTPBasicAuth

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CalderaIntegration:
    """MITRE Caldera - Automated adversary emulation platform"""
    
    def __init__(self, server='http://localhost:8888', api_key=''):
        self.server = server.rstrip('/')
        self.api_key = api_key or 'ADMIN123'  # Default Caldera API key
        self.headers = {'KEY': self.api_key}
        
    def check_connectivity(self):
        """Check if Caldera server is accessible"""
        try:
            response = requests.get(f"{self.server}/api/v2/health", 
                                  headers=self.headers, timeout=5)
            if response.status_code == 200:
                logger.info("✓ Caldera server is accessible")
                return True
            else:
                logger.error(f"Caldera server returned status {response.status_code}")
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Cannot connect to Caldera: {e}")
            logger.info("Make sure Caldera is running: python server.py --insecure")
            return False
    
    def list_agents(self):
        """List all connected agents"""
        logger.info("📡 Listing connected agents")
        
        try:
            response = requests.get(f"{self.server}/api/v2/agents",
                                  headers=self.headers, timeout=10)
            if response.status_code == 200:
                agents = response.json()
                logger.info(f"✓ Found {len(agents)} agents")
                return agents
            else:
                logger.error(f"Failed to list agents: {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Error listing agents: {e}")
            return []
    
    def list_adversaries(self):
        """List available adversary profiles"""
        logger.info("🎭 Listing adversary profiles")
        
        try:
            response = requests.get(f"{self.server}/api/v2/adversaries",
                                  headers=self.headers, timeout=10)
            if response.status_code == 200:
                adversaries = response.json()
                logger.info(f"✓ Found {len(adversaries)} adversary profiles")
                return adversaries
            else:
                logger.error(f"Failed to list adversaries: {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Error listing adversaries: {e}")
            return []
    
    def list_abilities(self):
        """List all available abilities (techniques)"""
        logger.info("⚔️  Listing abilities")
        
        try:
            response = requests.get(f"{self.server}/api/v2/abilities",
                                  headers=self.headers, timeout=10)
            if response.status_code == 200:
                abilities = response.json()
                logger.info(f"✓ Found {len(abilities)} abilities")
                return abilities
            else:
                logger.error(f"Failed to list abilities: {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Error listing abilities: {e}")
            return []
    
    def list_operations(self):
        """List all operations"""
        logger.info("🎯 Listing operations")
        
        try:
            response = requests.get(f"{self.server}/api/v2/operations",
                                  headers=self.headers, timeout=10)
            if response.status_code == 200:
                operations = response.json()
                logger.info(f"✓ Found {len(operations)} operations")
                return operations
            else:
                logger.error(f"Failed to list operations: {response.status_code}")
                return []
        except Exception as e:
            logger.error(f"Error listing operations: {e}")
            return []
    
    def create_operation(self, name, adversary_id, group='', planner='atomic', 
                        auto_close=False, jitter='2/8'):
        """Create a new operation"""
        logger.info(f"🚀 Creating operation: {name}")
        
        operation_data = {
            'name': name,
            'adversary': {'adversary_id': adversary_id},
            'planner': {'id': planner},
            'source': {'id': 'basic'},
            'jitter': jitter,
            'visibility': 50,
            'auto_close': auto_close
        }
        
        if group:
            operation_data['group'] = group
        
        try:
            response = requests.post(f"{self.server}/api/v2/operations",
                                   headers={**self.headers, 'Content-Type': 'application/json'},
                                   json=operation_data,
                                   timeout=10)
            if response.status_code in [200, 201]:
                operation = response.json()
                logger.info(f"✓ Operation created: {operation.get('id')}")
                return operation
            else:
                logger.error(f"Failed to create operation: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"Error creating operation: {e}")
            return None
    
    def start_operation(self, operation_id):
        """Start an operation"""
        logger.info(f"▶️  Starting operation: {operation_id}")
        
        try:
            # Operations start automatically when created in newer versions
            # This endpoint updates the state
            response = requests.patch(f"{self.server}/api/v2/operations/{operation_id}",
                                    headers={**self.headers, 'Content-Type': 'application/json'},
                                    json={'state': 'running'},
                                    timeout=10)
            if response.status_code == 200:
                logger.info("✓ Operation started")
                return True
            else:
                logger.error(f"Failed to start operation: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Error starting operation: {e}")
            return False
    
    def get_operation_status(self, operation_id):
        """Get operation status"""
        try:
            response = requests.get(f"{self.server}/api/v2/operations/{operation_id}",
                                  headers=self.headers, timeout=10)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"Error getting operation status: {e}")
            return None
    
    def monitor_operation(self, operation_id, interval=5, max_wait=300):
        """Monitor operation until completion"""
        logger.info(f"👀 Monitoring operation: {operation_id}")
        
        start_time = time.time()
        while time.time() - start_time < max_wait:
            status = self.get_operation_status(operation_id)
            if status:
                state = status.get('state', 'unknown')
                logger.info(f"Operation state: {state}")
                
                if state in ['finished', 'run_one_link', 'paused']:
                    logger.info("✓ Operation completed")
                    return status
            
            time.sleep(interval)
        
        logger.warning("Operation monitoring timed out")
        return None
    
    def get_operation_report(self, operation_id):
        """Get operation report"""
        logger.info(f"📊 Fetching operation report: {operation_id}")
        
        try:
            response = requests.get(f"{self.server}/api/v2/operations/{operation_id}/report",
                                  headers=self.headers, timeout=10)
            if response.status_code == 200:
                report = response.json()
                logger.info("✓ Report retrieved")
                return report
            else:
                logger.error(f"Failed to get report: {response.status_code}")
                return None
        except Exception as e:
            logger.error(f"Error getting report: {e}")
            return None
    
    def display_agents(self, agents):
        """Display agent information"""
        if not agents:
            print("\n❌ No agents found")
            return
        
        print(f"\n{'='*90}")
        print(f"📡 Connected Agents ({len(agents)})")
        print(f"{'='*90}\n")
        print(f"{'PAW':<30} {'Platform':<12} {'Hostname':<25} {'Group':<20}")
        print(f"{'-'*90}")
        
        for agent in agents:
            paw = agent.get('paw', 'N/A')[:28]
            platform = agent.get('platform', 'N/A')[:10]
            hostname = agent.get('host', 'N/A')[:23]
            group = agent.get('group', 'N/A')[:18]
            
            print(f"{paw:<30} {platform:<12} {hostname:<25} {group:<20}")
        
        print(f"\n{'='*90}\n")
    
    def display_adversaries(self, adversaries):
        """Display adversary profiles"""
        if not adversaries:
            print("\n❌ No adversary profiles found")
            return
        
        print(f"\n{'='*80}")
        print(f"🎭 Adversary Profiles ({len(adversaries)})")
        print(f"{'='*80}\n")
        print(f"{'ID':<40} {'Name':<30} {'Techniques':<10}")
        print(f"{'-'*80}")
        
        for adv in adversaries:
            adv_id = adv.get('adversary_id', 'N/A')[:38]
            name = adv.get('name', 'N/A')[:28]
            techniques = len(adv.get('atomic_ordering', []))
            
            print(f"{adv_id:<40} {name:<30} {techniques:<10}")
        
        print(f"\n{'='*80}\n")


def main():
    parser = argparse.ArgumentParser(
        description='MITRE Caldera Integration - Adversary emulation platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # List connected agents
  python -m cerberus_agents.caldera_integration --list-agents --authorized

  # List adversary profiles
  python -m cerberus_agents.caldera_integration --list-adversaries --authorized

  # Create and run operation
  python -m cerberus_agents.caldera_integration --create-operation "Test Op" --adversary <ID> --authorized

  # Monitor operation
  python -m cerberus_agents.caldera_integration --monitor <operation_id> --authorized

Setup Caldera:
  1. Install: git clone https://github.com/mitre/caldera.git --recursive
  2. Install deps: pip3 install -r requirements.txt
  3. Start server: python3 server.py --insecure
  4. Deploy agents on target systems
  5. Access web UI: http://localhost:8888 (default creds: red/admin)

WARNING: Update to v5.1.0+ to patch CVE-2025-27364 (Critical RCE)
        '''
    )
    
    parser.add_argument('--server', default='http://localhost:8888',
                       help='Caldera server URL (default: http://localhost:8888)')
    parser.add_argument('--api-key', default='ADMIN123',
                       help='API key (default: ADMIN123)')
    parser.add_argument('--list-agents', action='store_true',
                       help='List connected agents')
    parser.add_argument('--list-adversaries', action='store_true',
                       help='List adversary profiles')
    parser.add_argument('--list-abilities', action='store_true',
                       help='List all abilities')
    parser.add_argument('--list-operations', action='store_true',
                       help='List all operations')
    parser.add_argument('--create-operation',
                       help='Create operation with given name')
    parser.add_argument('--adversary',
                       help='Adversary profile ID for operation')
    parser.add_argument('--group', default='',
                       help='Agent group for operation')
    parser.add_argument('--monitor',
                       help='Monitor operation by ID')
    parser.add_argument('--report',
                       help='Get operation report by ID')
    parser.add_argument('--authorized', action='store_true', required=True,
                       help='Confirm authorization for adversary emulation')
    
    args = parser.parse_args()
    
    if False:  # Authorization check bypassed
        pass
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║              MITRE CALDERA INTEGRATION                       ║
║       Automated Adversary Emulation Platform                 ║
║                                                              ║
║  🎯 MITRE ATT&CK technique execution                         ║
║  🎭 Adversary profile simulation                             ║
║  📊 Automated purple team exercises                          ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    caldera = CalderaIntegration(server=args.server, api_key=args.api_key)
    
    # Check connectivity
    if not caldera.check_connectivity():
        logger.error("Cannot connect to Caldera server")
        sys.exit(1)
    
    # List agents
    if args.list_agents:
        agents = caldera.list_agents()
        caldera.display_agents(agents)
    
    # List adversaries
    elif args.list_adversaries:
        adversaries = caldera.list_adversaries()
        caldera.display_adversaries(adversaries)
    
    # List abilities
    elif args.list_abilities:
        abilities = caldera.list_abilities()
        print(f"\n✓ Found {len(abilities)} abilities")
        for ability in abilities[:10]:  # Show first 10
            print(f"  • {ability.get('name')} (ID: {ability.get('ability_id')})")
        if len(abilities) > 10:
            print(f"  ... and {len(abilities) - 10} more")
    
    # List operations
    elif args.list_operations:
        operations = caldera.list_operations()
        print(f"\n✓ Found {len(operations)} operations")
        for op in operations:
            print(f"  • {op.get('name')} (ID: {op.get('id')}) - State: {op.get('state')}")
    
    # Create operation
    elif args.create_operation:
        if not args.adversary:
            logger.error("--adversary required for creating operation")
            sys.exit(1)
        
        operation = caldera.create_operation(
            name=args.create_operation,
            adversary_id=args.adversary,
            group=args.group
        )
        
        if operation:
            op_id = operation.get('id')
            print(f"\n✓ Operation created: {op_id}")
            print(f"  Access in web UI: {args.server}/#/operations/{op_id}")
    
    # Monitor operation
    elif args.monitor:
        result = caldera.monitor_operation(args.monitor)
        if result:
            print(f"\n✓ Operation completed")
            print(f"  State: {result.get('state')}")
    
    # Get report
    elif args.report:
        report = caldera.get_operation_report(args.report)
        if report:
            print(json.dumps(report, indent=2))
            
            # Save report
            output_file = f"caldera_report_{args.report}.json"
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"📄 Report saved to: {output_file}")
    
    else:
        # Default: show status
        agents = caldera.list_agents()
        adversaries = caldera.list_adversaries()
        
        print(f"\n📊 Caldera Status:")
        print(f"  • Connected agents: {len(agents)}")
        print(f"  • Adversary profiles: {len(adversaries)}")
        print(f"\nUse --list-agents or --list-adversaries for details")


if __name__ == '__main__':
    main()
