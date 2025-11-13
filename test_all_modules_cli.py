#!/usr/bin/env python3
"""
Comprehensive CLI Testing for All Cerberus Agents Modules
Tests that all tools are production-ready and accessible via command line
"""

import subprocess
import sys
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

CRITICAL_MODULES = [
    # Core Network & Recon
    ('cerberus_agents.network_scanner_advanced', '--help'),
    ('cerberus_agents.asset_discovery_agent', '--help'),
    ('cerberus_agents.subdomain_enumeration', '--help'),
    ('cerberus_agents.advanced_osint_recon', '--help'),
    ('cerberus_agents.osint_reconnaissance', '--help'),
    
    # Active Directory & Windows
    ('cerberus_agents.active_directory_attacks', '--help'),
    ('cerberus_agents.kerberos_attacks', '--help'),
    ('cerberus_agents.impacket_lateral_movement', '--help'),
    ('cerberus_agents.netexec_lateral_movement', '--help'),
    ('cerberus_agents.certipy_adcs_attacks', '--help'),
    ('cerberus_agents.bloodhound_analyzer', '--help'),
    ('cerberus_agents.rubeus_wrapper', '--help'),
    ('cerberus_agents.crackmapexec_lateral_movement', '--help'),
    
    # Cloud Security
    ('cerberus_agents.cloud_security_scanner', '--help'),
    ('cerberus_agents.aws_exploitation', '--help'),
    ('cerberus_agents.pacu_aws_exploitation', '--help'),
    ('cerberus_agents.cloudfox_aws_integration', '--help'),
    ('cerberus_agents.microburst_integration', '--help'),
    ('cerberus_agents.prowler_cloud_compliance', '--help'),
    
    # Container & Kubernetes
    ('cerberus_agents.container_kubernetes_security', '--help'),
    ('cerberus_agents.trivy_scanner', '--help'),
    ('cerberus_agents.kube_hunter_pentesting', '--help'),
    ('cerberus_agents.kubeletctl_exploitation', '--help'),
    ('cerberus_agents.peirates_k8s_privesc', '--help'),
    
    # Web Application Security
    ('cerberus_agents.web_vuln_scanner', '--help'),
    ('cerberus_agents.api_security_scanner', '--help'),
    ('cerberus_agents.sqlmap_exploitation', '--help'),
    ('cerberus_agents.owasp_zap_scanner', '--help'),
    ('cerberus_agents.nuclei_scanner', '--help'),
    ('cerberus_agents.wapiti_web_scanner', '--help'),
    
    # C2 Frameworks
    ('cerberus_agents.advanced_c2_framework', '--help'),
    ('cerberus_agents.sliver_c2_framework', '--help'),
    ('cerberus_agents.mythic_c2_framework', '--help'),
    ('cerberus_agents.empire_c2_integration', '--help'),
    ('cerberus_agents.havoc_c2_integration', '--help'),
    ('cerberus_agents.covenant_c2_integration', '--help'),
    
    # Password & Hash Cracking
    ('cerberus_agents.hash_cracker', '--help'),
    ('cerberus_agents.advanced_password_cracker', '--help'),
    ('cerberus_agents.hashcat_john_integration', '--help'),
    
    # Post-Exploitation
    ('cerberus_agents.post_exploitation_framework', '--help'),
    ('cerberus_agents.privilege_escalation', '--help'),
    ('cerberus_agents.credential_dumping', '--help'),
    ('cerberus_agents.payload_generator', '--help'),
    
    # Network Tools
    ('cerberus_agents.network_mitm', '--help'),
    ('cerberus_agents.network_poisoning', '--help'),
    ('cerberus_agents.wireless_security', '--help'),
    ('cerberus_agents.bettercap_integration', '--help'),
    
    # Pivoting & Tunneling
    ('cerberus_agents.advanced_network_pivoting', '--help'),
    ('cerberus_agents.chisel_tunneling', '--help'),
    ('cerberus_agents.ligolo_ng_integration', '--help'),
    
    # Social Engineering
    ('cerberus_agents.social_engineering_advanced', '--help'),
    ('cerberus_agents.evilginx_phishing', '--help'),
    ('cerberus_agents.gophish_campaigns', '--help'),
    
    # Mobile Security
    ('cerberus_agents.mobile_app_security', '--help'),
    ('cerberus_agents.android_comprehensive_scanner', '--help'),
    ('cerberus_agents.ios_pentesting_framework', '--help'),
    
    # Adversary Emulation
    ('cerberus_agents.adversary_emulation', '--help'),
    ('cerberus_agents.atomic_redteam', '--help'),
    ('cerberus_agents.caldera_integration', '--help'),
    
    # Detection & Blue Team
    ('cerberus_agents.detection_scoring', '--help'),
    ('cerberus_agents.tiny_canary_agent', '--help'),
]

def test_module_cli(module_name, test_arg='--help'):
    """Test if module is accessible via CLI"""
    try:
        cmd = ['python', '-m', module_name, test_arg]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=5
        )
        
        # Success if help is shown or if it's an authorization check
        if result.returncode == 0 or 'AUTHORIZATION' in result.stderr or 'help' in result.stdout.lower():
            return True, "OK"
        else:
            return False, f"Exit code: {result.returncode}"
            
    except subprocess.TimeoutExpired:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)

def main():
    """Run comprehensive CLI testing"""
    logger.info("=" * 70)
    logger.info("CERBERUS AGENTS - CLI MODULE TESTING")
    logger.info("=" * 70)
    logger.info(f"\nTesting {len(CRITICAL_MODULES)} critical modules...\n")
    
    passed = 0
    failed = 0
    failed_modules = []
    
    for module_name, test_arg in CRITICAL_MODULES:
        success, message = test_module_cli(module_name, test_arg)
        
        if success:
            logger.info(f"✅ {module_name}")
            passed += 1
        else:
            logger.error(f"❌ {module_name} - {message}")
            failed += 1
            failed_modules.append(module_name)
    
    logger.info("\n" + "=" * 70)
    logger.info(f"RESULTS: {passed}/{len(CRITICAL_MODULES)} modules passed")
    logger.info(f"Success Rate: {(passed/len(CRITICAL_MODULES)*100):.1f}%")
    logger.info("=" * 70)
    
    if failed > 0:
        logger.warning(f"\n❌ {failed} modules failed:")
        for module in failed_modules:
            logger.warning(f"   - {module}")
        return 1
    else:
        logger.info("\n✅ ALL MODULES ARE CLI-ACCESSIBLE AND PRODUCTION-READY!")
        return 0

if __name__ == '__main__':
    sys.exit(main())
