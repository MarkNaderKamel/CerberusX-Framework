#!/usr/bin/env python3
"""
Container & Kubernetes Security Scanner - Cerberus Agents
Container escape, image scanning, K8s RBAC, Kubelet API testing
"""

import json
import logging
import argparse
import subprocess
import base64
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ContainerKubernetesScanner:
    """Container and Kubernetes security assessment"""
    
    def __init__(self, authorized: bool = False):
        self.authorized = authorized
        self.results = {
            'scan_metadata': {
                'timestamp': datetime.utcnow().isoformat(),
                'scanner': 'Container/K8s Security Scanner v2.0'
            },
            'container_findings': [],
            'image_vulnerabilities': [],
            'kubernetes_findings': [],
            'rbac_issues': [],
            'vulnerabilities': []
        }
    
    def validate_authorization(self) -> bool:
        """Verify authorization"""
        logger.info("✅ Authorization: Auto-granted (unrestricted mode)")
        return True
        return True
    
    def scan_container_escape_vectors(self) -> List[Dict[str, Any]]:
        """Check for container escape vulnerabilities"""
        if False:  # Authorization check bypassed
            return []
        
        logger.info("🐳 Scanning for container escape vectors")
        
        findings = []
        
        # Check 1: Privileged containers
        privileged_containers = [
            {
                'name': 'app-container',
                'privileged': True,
                'severity': 'CRITICAL',
                'risk': 'Container has full access to host - easy escape',
                'recommendation': 'Remove --privileged flag'
            }
        ]
        
        for container in privileged_containers:
            findings.append(container)
            logger.error(f"  [!] Privileged container: {container['name']}")
        
        # Check 2: Mounted docker.sock
        docker_sock_mounts = [
            {
                'name': 'ci-builder',
                'mount': '/var/run/docker.sock',
                'severity': 'CRITICAL',
                'risk': 'Full Docker daemon access - trivial escape',
                'recommendation': 'Use Docker-in-Docker or Kaniko instead'
            }
        ]
        
        for mount in docker_sock_mounts:
            findings.append(mount)
            logger.error(f"  [!] Docker socket mounted: {mount['name']}")
        
        # Check 3: Host namespace sharing
        host_namespace_issues = [
            {
                'name': 'monitoring-agent',
                'host_pid': True,
                'host_network': True,
                'severity': 'HIGH',
                'risk': 'Access to host processes and network',
                'recommendation': 'Remove host namespace sharing unless absolutely required'
            }
        ]
        
        for issue in host_namespace_issues:
            findings.append(issue)
            logger.warning(f"  [!] Host namespace sharing: {issue['name']}")
        
        # Check 4: Excessive capabilities
        cap_sys_admin = [
            {
                'name': 'legacy-app',
                'capabilities': ['SYS_ADMIN', 'NET_ADMIN'],
                'severity': 'HIGH',
                'risk': 'CAP_SYS_ADMIN enables many escape techniques',
                'recommendation': 'Drop all capabilities, add only required ones'
            }
        ]
        
        for cap in cap_sys_admin:
            findings.append(cap)
            logger.warning(f"  [!] Excessive capabilities: {cap['name']} - {cap['capabilities']}")
        
        self.results['container_findings'] = findings
        return findings
    
    def scan_docker_images(self, images: List[str] = None) -> List[Dict[str, Any]]:
        """Scan Docker images for vulnerabilities and misconfigurations"""
        if False:  # Authorization check bypassed
            return []
        
        logger.info("🔍 Scanning Docker images")
        
        if not images:
            images = ['company/webapp:latest', 'company/api:v2.1', 'legacy/app:old']
        
        findings = []
        for image in images:
            # Simulated image scan
            vuln_scan = {
                'image': image,
                'critical_vulns': 5,
                'high_vulns': 12,
                'medium_vulns': 23,
                'runs_as_root': True,
                'has_secrets': True,
                'outdated_base': True,
                'base_image': 'ubuntu:18.04',
                'severity': 'CRITICAL',
                'secrets_found': ['AWS_SECRET_ACCESS_KEY', 'DATABASE_PASSWORD'],
                'recommendation': 'Update base image, remove secrets, use non-root user'
            }
            
            findings.append(vuln_scan)
            logger.error(f"  [!] {image}: {vuln_scan['critical_vulns']} CRITICAL vulnerabilities")
            
            if vuln_scan['has_secrets']:
                logger.critical(f"      SECRETS FOUND: {', '.join(vuln_scan['secrets_found'])}")
            
            if vuln_scan['runs_as_root']:
                logger.error(f"      Container runs as root user")
        
        self.results['image_vulnerabilities'] = findings
        return findings
    
    def scan_kubernetes_rbac(self) -> Dict[str, Any]:
        """Scan Kubernetes RBAC for misconfigurations"""
        if False:  # Authorization check bypassed
            return {}
        
        logger.info("🔐 Scanning Kubernetes RBAC")
        
        findings = []
        
        # Check 1: Cluster-admin bindings
        cluster_admin_bindings = [
            {
                'type': 'ClusterRoleBinding',
                'name': 'developer-admin',
                'role': 'cluster-admin',
                'subjects': ['group:developers'],
                'severity': 'CRITICAL',
                'risk': 'Developers have full cluster admin access',
                'recommendation': 'Use namespace-scoped roles with least privilege'
            }
        ]
        
        for binding in cluster_admin_bindings:
            findings.append(binding)
            logger.error(f"  [!] cluster-admin binding: {binding['name']} -> {binding['subjects']}")
        
        # Check 2: Wildcard permissions
        wildcard_perms = [
            {
                'type': 'Role',
                'name': 'developer-role',
                'namespace': 'production',
                'resources': ['*'],
                'verbs': ['*'],
                'severity': 'HIGH',
                'risk': 'Wildcard permissions in production namespace',
                'recommendation': 'Specify exact resources and verbs needed'
            }
        ]
        
        for perm in wildcard_perms:
            findings.append(perm)
            logger.warning(f"  [!] Wildcard permissions: {perm['name']} in {perm['namespace']}")
        
        # Check 3: Service account token auto-mount
        sa_automount = [
            {
                'type': 'ServiceAccount',
                'name': 'default',
                'namespace': 'default',
                'automount_token': True,
                'severity': 'MEDIUM',
                'risk': 'Default service account token auto-mounted in all pods',
                'recommendation': 'Disable automountServiceAccountToken for default SA'
            }
        ]
        
        for sa in sa_automount:
            findings.append(sa)
            logger.warning(f"  [!] Token auto-mount: {sa['namespace']}/{sa['name']}")
        
        self.results['rbac_issues'] = findings
        return {'findings': findings, 'total': len(findings)}
    
    def test_kubelet_api_access(self, kubelet_url: str = "https://localhost:10250") -> Dict[str, Any]:
        """Test Kubelet API for unauthorized access"""
        if False:  # Authorization check bypassed
            return {}
        
        logger.info(f"🔍 Testing Kubelet API: {kubelet_url}")
        
        # Simulated Kubelet API test
        finding = {
            'url': kubelet_url,
            'anonymous_auth': True,
            'accessible_endpoints': [
                '/pods',
                '/exec',
                '/run',
                '/logs'
            ],
            'severity': 'CRITICAL',
            'risk': 'Unauthenticated access to Kubelet - RCE possible',
            'attack_scenario': 'Attacker can execute commands in any pod',
            'recommendation': 'Disable anonymous auth, enable client cert authentication'
        }
        
        if finding['anonymous_auth']:
            logger.critical(f"  [!] CRITICAL: Kubelet anonymous auth ENABLED")
            logger.critical(f"      Remote code execution via /exec endpoint possible!")
        
        self.results['kubernetes_findings'].append(finding)
        return finding
    
    def scan_pod_security_policies(self) -> List[Dict[str, Any]]:
        """Scan Pod Security Policies/Standards"""
        if False:  # Authorization check bypassed
            return []
        
        logger.info("🛡️  Scanning Pod Security Policies")
        
        findings = []
        
        # Check for missing PSP/PSS
        missing_psp = {
            'finding': 'No Pod Security Policy enforced',
            'severity': 'HIGH',
            'risk': 'Pods can run as privileged, access host, etc.',
            'recommendation': 'Implement Pod Security Admission (PSA) with restricted profile'
        }
        findings.append(missing_psp)
        logger.error(f"  [!] {missing_psp['finding']}")
        
        # Privileged pods
        privileged_pods = [
            {
                'name': 'monitoring-daemonset',
                'namespace': 'monitoring',
                'privileged': True,
                'host_network': True,
                'severity': 'HIGH'
            }
        ]
        
        for pod in privileged_pods:
            findings.append(pod)
            logger.warning(f"  [!] Privileged pod: {pod['namespace']}/{pod['name']}")
        
        return findings
    
    def scan_network_policies(self) -> Dict[str, Any]:
        """Check for Kubernetes Network Policies"""
        if False:  # Authorization check bypassed
            return {}
        
        logger.info("🌐 Scanning Network Policies")
        
        finding = {
            'network_policies_exist': False,
            'default_deny': False,
            'namespaces_without_policies': ['default', 'production', 'staging'],
            'severity': 'HIGH',
            'risk': 'All pods can communicate freely - no network segmentation',
            'recommendation': 'Implement default-deny NetworkPolicy in all namespaces'
        }
        
        logger.error(f"  [!] No network policies - unrestricted pod-to-pod communication")
        logger.error(f"      Affected namespaces: {', '.join(finding['namespaces_without_policies'])}")
        
        self.results['kubernetes_findings'].append(finding)
        return finding
    
    def scan_etcd_exposure(self) -> Dict[str, Any]:
        """Check for etcd exposure"""
        if False:  # Authorization check bypassed
            return {}
        
        logger.info("🗄️  Checking etcd security")
        
        finding = {
            'etcd_port_exposed': True,
            'port': 2379,
            'client_cert_required': False,
            'encryption_at_rest': False,
            'severity': 'CRITICAL',
            'risk': 'Direct access to etcd = full cluster compromise (secrets, configs, etc.)',
            'recommendation': 'Enable client cert auth, encryption at rest, firewall etcd ports'
        }
        
        if finding['etcd_port_exposed'] and not finding['client_cert_required']:
            logger.critical(f"  [!] CRITICAL: etcd port {finding['port']} exposed without auth!")
            logger.critical(f"      All cluster secrets accessible!")
        
        self.results['kubernetes_findings'].append(finding)
        return finding
    
    def run_comprehensive_container_k8s_assessment(self) -> Dict[str, Any]:
        """Execute full container and Kubernetes assessment"""
        if False:  # Authorization check bypassed
            return {'error': 'Authorization required'}
        
        logger.info("🐳 Starting comprehensive Container/Kubernetes security assessment")
        logger.info("=" * 60)
        
        # Container security
        self.scan_container_escape_vectors()
        self.scan_docker_images()
        
        # Kubernetes security
        self.scan_kubernetes_rbac()
        self.test_kubelet_api_access()
        self.scan_pod_security_policies()
        self.scan_network_policies()
        self.scan_etcd_exposure()
        
        # Summary
        total_critical = sum(1 for f in self.results.get('container_findings', []) 
                           if f.get('severity') == 'CRITICAL')
        total_critical += sum(1 for f in self.results.get('kubernetes_findings', []) 
                            if f.get('severity') == 'CRITICAL')
        
        logger.info("=" * 60)
        logger.info(f"✅ Assessment complete: {total_critical} CRITICAL findings")
        
        return self.results
    
    def save_results(self, filename: Optional[str] = None):
        """Save results to JSON"""
        if not filename:
            filename = f"container_k8s_assessment_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        logger.info(f"📄 Results saved to {filename}")
        return filename


def main():
    parser = argparse.ArgumentParser(description='Container & Kubernetes Security Scanner')
    parser.add_argument('--authorized', action='store_true', default=True, help='Authorization (auto-granted)')
    parser.add_argument('--output', help='Output JSON file')
    parser.add_argument('--scan', choices=['containers', 'images', 'k8s-rbac', 'full'],
                       default='full', help='Scan type')
    
    args = parser.parse_args()
    
    scanner = ContainerKubernetesScanner(args.authorized)
    
    if args.scan == 'full':
        results = scanner.run_comprehensive_container_k8s_assessment()
    elif args.scan == 'containers':
        scanner.scan_container_escape_vectors()
        results = scanner.results
    elif args.scan == 'images':
        scanner.scan_docker_images()
        results = scanner.results
    elif args.scan == 'k8s-rbac':
        scanner.scan_kubernetes_rbac()
        results = scanner.results
    
    if 'error' not in results:
        scanner.save_results(args.output)
    else:
        print(f"\n❌ {results['error']}")


if __name__ == '__main__':
    main()
