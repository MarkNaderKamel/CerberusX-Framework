#!/usr/bin/env python3
"""
Comprehensive Module Import Testing
Tests all 128 Cerberus Agents modules for import integrity
"""

import sys
import importlib
import traceback
from pathlib import Path

# All 128 modules from the registry
MODULES = [
    "advanced_osint_phone_email",
    "advanced_osint_recon",
    "automated_recon_reporter",
    "cctv_camera_discovery",
    "metagoofil_integration",
    "osint_reconnaissance",
    "subdomain_enumeration",
    "subfinder_subdomain_discovery",
    "theharvester_integration",
    "advanced_network_pivoting",
    "android_comprehensive_scanner",
    "android_mobsf_scanner",
    "api_security_scanner",
    "chisel_tunneling",
    "cloud_security_scanner",
    "database_security_scanner",
    "ligolo_ng_integration",
    "naabu_port_scanner",
    "network_camera_pentesting",
    "network_mitm",
    "network_pivoting",
    "network_poisoning",
    "network_scanner_advanced",
    "protocol_security_scanner",
    "rustscan_integration",
    "ssl_tls_scanner",
    "trivy_scanner",
    "vulnerability_scanner",
    "wapiti_web_scanner",
    "web_server_scanner",
    "web_vuln_scanner",
    "aircrack_suite",
    "airgeddon_wrapper",
    "bettercap_integration",
    "wifi_pineapple_integration",
    "wifite2_automation",
    "wireless_security",
    "wpa3_cracker_wacker",
    "android_ssl_root_bypass",
    "donpapi_secrets_dumping",
    "feroxbuster_integration",
    "ffuf_integration",
    "httpx_http_probing",
    "katana_web_crawler",
    "sqlmap_exploitation",
    "cve_exploit_database",
    "aadinternals_integration",
    "active_directory_attacks",
    "advanced_c2_framework",
    "advanced_password_cracker",
    "adversary_emulation",
    "android_adb_exploitation",
    "android_frida_advanced",
    "android_jadx_decompiler",
    "bloodhound_analyzer",
    "certipy_adcs_attacks",
    "certipy_adcs_wrapper",
    "enum4linux_ng_integration",
    "evil_winrm_integration",
    "execution_adapter",
    "impacket_lateral_movement",
    "kerberos_attacks",
    "kerbrute_integration",
    "linwinpwn_ad_automation",
    "lsassy_credential_dumping",
    "netexec_integration",
    "netexec_lateral_movement",
    "payload_generator",
    "roadtools_integration",
    "social_engineering_advanced",
    "aws_exploitation",
    "cloudfox_aws_integration",
    "graphrunner_integration",
    "microburst_integration",
    "scoutsuite_cloud_audit",
    "cdk_container_escape",
    "container_kubernetes_security",
    "deepce_container_enum",
    "kube_hunter_pentesting",
    "kubeletctl_exploitation",
    "peirates_k8s_privesc",
    "android_apk_analyzer",
    "android_apkid_detector",
    "android_apktool_framework",
    "android_bytecode_analyzer",
    "android_dex2jar_converter",
    "android_drozer_framework",
    "android_frida_framework",
    "android_objection_toolkit",
    "android_pentesting_suite",
    "ios_frida_pentesting",
    "ios_pentesting_framework",
    "macos_red_team_extended",
    "mobile_app_security",
    "crackmapexec_lateral_movement",
    "credential_dumping",
    "hash_cracker",
    "hashcat_john_integration",
    "c2_integration",
    "covenant_c2_integration",
    "data_exfiltration",
    "havoc_c2_integration",
    "merlin_c2_integration",
    "evilginx_phishing",
    "gophish_campaigns",
    "social_engineering",
    "atomic_redteam",
    "caldera_integration",
    "detection_scoring",
    "alcatraz_obfuscator",
    "exploit_development",
    "fuzzing_framework",
    "ghidra_wrapper",
    "mangle_obfuscation",
    "post_exploitation_framework",
    "sharpshooter_integration",
    "ai_image_intelligence",
    "garak_ai_redteam",
    "responder_llmnr",
    "asset_discovery_agent",
    "coercer_ntlm_coercion",
    "edr_evasion_toolkit",
    "gowitness_screenshots",
    "module_registry",
    "privilege_escalation",
    "prompt_orchestrator",
    "rubeus_wrapper",
    "sn1per_integration"
]

def test_module_import(module_name):
    """Test a single module import"""
    try:
        full_name = f"cerberus_agents.{module_name}"
        importlib.import_module(full_name)
        return True, None
    except Exception as e:
        error_msg = f"{type(e).__name__}: {str(e)}"
        return False, error_msg

def main():
    print("=" * 80)
    print("CERBERUS AGENTS - COMPREHENSIVE IMPORT TEST")
    print("=" * 80)
    print(f"Testing {len(MODULES)} modules...\n")
    
    passed = []
    failed = []
    
    for i, module in enumerate(MODULES, 1):
        success, error = test_module_import(module)
        
        if success:
            passed.append(module)
            print(f"✓ [{i:3d}/128] {module}")
        else:
            failed.append((module, error))
            print(f"✗ [{i:3d}/128] {module}")
            print(f"    Error: {error}")
    
    print("\n" + "=" * 80)
    print("IMPORT TEST RESULTS")
    print("=" * 80)
    print(f"✓ Passed: {len(passed)}/128 ({len(passed)/128*100:.1f}%)")
    print(f"✗ Failed: {len(failed)}/128 ({len(failed)/128*100:.1f}%)")
    
    if failed:
        print("\n" + "=" * 80)
        print("FAILED IMPORTS")
        print("=" * 80)
        for module, error in failed:
            print(f"\n✗ {module}")
            print(f"  {error}")
    
    print("\n" + "=" * 80)
    
    return len(failed) == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
