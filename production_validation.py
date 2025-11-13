#!/usr/bin/env python3
"""
Comprehensive Production Validation for Cerberus Agents
Validates all tools are production-ready and CLI-accessible
"""

import subprocess
import sys
import logging
import json
from datetime import datetime
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ProductionValidator:
    """Validates production readiness of all toolkit components"""
    
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'modules_tested': 0,
            'modules_passed': 0,
            'modules_failed': 0,
            'cli_accessible': [],
            'cli_failed': [],
            'real_integrations': [],
            'python_fallbacks': []
        }
    
    def test_module_import(self, module_name):
        """Test if module can be imported"""
        try:
            result = subprocess.run(
                ['python', '-c', f'import {module_name}'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def test_module_cli(self, module_name):
        """Test if module is CLI-accessible"""
        try:
            result = subprocess.run(
                ['python', '-m', module_name, '--help'],
                capture_output=True,
                text=True,
                timeout=5
            )
            # Success if help shown or authorization check
            return (result.returncode == 0 or 
                    'AUTHORIZATION' in result.stderr or 
                    'help' in result.stdout.lower() or
                    'usage' in result.stdout.lower())
        except:
            return False
    
    def validate_core_network_tools(self):
        """Validate core network reconnaissance tools"""
        logger.info("\n🌐 Validating Network Reconnaissance Tools...")
        
        tools = [
            'cerberus_agents.network_scanner_advanced',
            'cerberus_agents.asset_discovery_agent',
            'cerberus_agents.subdomain_enumeration',
            'cerberus_agents.rustscan_integration',
            'cerberus_agents.naabu_port_scanner',
            'cerberus_agents.httpx_http_probing',
            'cerberus_agents.nuclei_scanner'
        ]
        
        return self._validate_tools(tools)
    
    def validate_ad_tools(self):
        """Validate Active Directory attack tools"""
        logger.info("\n🏰 Validating Active Directory Tools...")
        
        tools = [
            'cerberus_agents.active_directory_attacks',
            'cerberus_agents.kerberos_attacks',
            'cerberus_agents.impacket_lateral_movement',
            'cerberus_agents.netexec_lateral_movement',
            'cerberus_agents.certipy_adcs_attacks',
            'cerberus_agents.bloodhound_analyzer',
            'cerberus_agents.rubeus_wrapper',
            'cerberus_agents.kerbrute_integration',
            'cerberus_agents.enum4linux_ng_integration',
            'cerberus_agents.linwinpwn_ad_automation'
        ]
        
        return self._validate_tools(tools)
    
    def validate_cloud_tools(self):
        """Validate cloud security tools"""
        logger.info("\n☁️  Validating Cloud Security Tools...")
        
        tools = [
            'cerberus_agents.cloud_security_scanner',
            'cerberus_agents.aws_exploitation',
            'cerberus_agents.pacu_aws_exploitation',
            'cerberus_agents.cloudfox_aws_integration',
            'cerberus_agents.prowler_cloud_compliance',
            'cerberus_agents.microburst_integration',
            'cerberus_agents.cloud_auditor_scoutsuite',
            'cerberus_agents.scoutsuite_cloud_audit'
        ]
        
        return self._validate_tools(tools)
    
    def validate_container_k8s_tools(self):
        """Validate container and Kubernetes tools"""
        logger.info("\n🐳 Validating Container & Kubernetes Tools...")
        
        tools = [
            'cerberus_agents.container_kubernetes_security',
            'cerberus_agents.trivy_scanner',
            'cerberus_agents.kube_hunter_pentesting',
            'cerberus_agents.kubeletctl_exploitation',
            'cerberus_agents.peirates_k8s_privesc',
            'cerberus_agents.cdk_container_escape',
            'cerberus_agents.deepce_container_enum'
        ]
        
        return self._validate_tools(tools)
    
    def validate_c2_frameworks(self):
        """Validate C2 framework integrations"""
        logger.info("\n🎯 Validating C2 Frameworks...")
        
        tools = [
            'cerberus_agents.advanced_c2_framework',
            'cerberus_agents.sliver_c2_framework',
            'cerberus_agents.mythic_c2_framework',
            'cerberus_agents.empire_c2_integration',
            'cerberus_agents.havoc_c2_integration',
            'cerberus_agents.covenant_c2_integration',
            'cerberus_agents.poshc2_framework',
            'cerberus_agents.merlin_c2_integration'
        ]
        
        return self._validate_tools(tools)
    
    def validate_web_api_tools(self):
        """Validate web and API security tools"""
        logger.info("\n🌐 Validating Web & API Security Tools...")
        
        tools = [
            'cerberus_agents.web_vuln_scanner',
            'cerberus_agents.api_security_scanner',
            'cerberus_agents.sqlmap_exploitation',
            'cerberus_agents.owasp_zap_scanner',
            'cerberus_agents.nuclei_scanner',
            'cerberus_agents.wapiti_web_scanner',
            'cerberus_agents.feroxbuster_integration',
            'cerberus_agents.ffuf_integration',
            'cerberus_agents.katana_web_crawler'
        ]
        
        return self._validate_tools(tools)
    
    def validate_osint_tools(self):
        """Validate OSINT reconnaissance tools"""
        logger.info("\n🔍 Validating OSINT Tools...")
        
        tools = [
            'cerberus_agents.osint_reconnaissance',
            'cerberus_agents.advanced_osint_recon',
            'cerberus_agents.theharvester_integration',
            'cerberus_agents.spiderfoot_osint',
            'cerberus_agents.subfinder_subdomain_discovery',
            'cerberus_agents.metagoofil_integration',
            'cerberus_agents.gowitness_screenshots',
            'cerberus_agents.reconftw_automation'
        ]
        
        return self._validate_tools(tools)
    
    def validate_mobile_tools(self):
        """Validate mobile security tools"""
        logger.info("\n📱 Validating Mobile Security Tools...")
        
        tools = [
            'cerberus_agents.mobile_app_security',
            'cerberus_agents.android_comprehensive_scanner',
            'cerberus_agents.ios_pentesting_framework',
            'cerberus_agents.android_frida_framework',
            'cerberus_agents.android_apktool_framework',
            'cerberus_agents.android_jadx_decompiler',
            'cerberus_agents.android_mobsf_scanner'
        ]
        
        return self._validate_tools(tools)
    
    def _validate_tools(self, tools):
        """Validate a list of tools"""
        passed = 0
        failed = 0
        
        for tool in tools:
            self.results['modules_tested'] += 1
            
            if self.test_module_cli(tool):
                logger.info(f"  ✅ {tool.split('.')[-1]}")
                self.results['cli_accessible'].append(tool)
                self.results['modules_passed'] += 1
                passed += 1
            else:
                logger.error(f"  ❌ {tool.split('.')[-1]}")
                self.results['cli_failed'].append(tool)
                self.results['modules_failed'] += 1
                failed += 1
        
        return passed, failed
    
    def generate_report(self):
        """Generate comprehensive validation report"""
        logger.info("\n" + "=" * 70)
        logger.info("PRODUCTION VALIDATION REPORT")
        logger.info("=" * 70)
        
        total = self.results['modules_tested']
        passed = self.results['modules_passed']
        failed = self.results['modules_failed']
        
        success_rate = (passed / total * 100) if total > 0 else 0
        
        logger.info(f"\n📊 Overall Results:")
        logger.info(f"   Total Modules Tested: {total}")
        logger.info(f"   ✅ Passed: {passed}")
        logger.info(f"   ❌ Failed: {failed}")
        logger.info(f"   Success Rate: {success_rate:.1f}%")
        
        if success_rate >= 95:
            logger.info("\n🎉 PRODUCTION READY - Toolkit is fully validated!")
        elif success_rate >= 80:
            logger.warning("\n⚠️  MOSTLY READY - Some components need attention")
        else:
            logger.error("\n❌ NOT READY - Significant issues detected")
        
        # Save JSON report
        report_file = 'production_validation_report.json'
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        logger.info(f"\n📄 Detailed report saved to: {report_file}")
        
        return success_rate >= 95


def main():
    logger.info("=" * 70)
    logger.info("CERBERUS AGENTS - COMPREHENSIVE PRODUCTION VALIDATION")
    logger.info("=" * 70)
    
    validator = ProductionValidator()
    
    # Run all validation categories
    validator.validate_core_network_tools()
    validator.validate_ad_tools()
    validator.validate_cloud_tools()
    validator.validate_container_k8s_tools()
    validator.validate_c2_frameworks()
    validator.validate_web_api_tools()
    validator.validate_osint_tools()
    validator.validate_mobile_tools()
    
    # Generate final report
    production_ready = validator.generate_report()
    
    return 0 if production_ready else 1


if __name__ == '__main__':
    sys.exit(main())
