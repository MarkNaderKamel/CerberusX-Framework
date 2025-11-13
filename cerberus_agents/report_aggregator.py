#!/usr/bin/env python3
"""
Report Aggregator

Aggregates and analyzes reports from all agents to create a comprehensive
security assessment report with statistics and recommendations.

Usage:
    python -m cerberus_agents.report_aggregator --scan-dir .
"""

import argparse
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List
import glob

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ReportAggregator:
    def __init__(self, scan_dir: str = "."):
        self.scan_dir = Path(scan_dir)
        self.reports = {
            "assets": [],
            "recon": [],
            "credentials": [],
            "vulnerabilities": [],
            "forensics": [],
            "tasks": []
        }
        self.aggregated_data = {}
    
    def collect_reports(self):
        """Collect all JSON reports"""
        logger.info("📂 Collecting reports...")
        
        for json_file in self.scan_dir.glob("**/*.json"):
            try:
                with json_file.open() as f:
                    data = json.load(f)
                    
                    if "assets" in data:
                        self.reports["assets"].append(data)
                    elif "subdomains" in data:
                        self.reports["recon"].append(data)
                    elif "audit_results" in data:
                        self.reports["credentials"].append(data)
                    elif "vulnerabilities" in data:
                        self.reports["vulnerabilities"].append(data)
                    elif "incident_id" in data or "forensics" in str(json_file):
                        self.reports["forensics"].append(data)
                    elif "tasks" in data or "orchestration" in str(json_file):
                        self.reports["tasks"].append(data)
                        
                logger.info(f"  ✓ Loaded: {json_file.name}")
            except Exception as e:
                logger.debug(f"  ⚠️  Failed to load {json_file}: {e}")
        
        total = sum(len(v) for v in self.reports.values())
        logger.info(f"\n✓ Collected {total} reports")
    
    def analyze_assets(self) -> Dict:
        """Analyze asset discovery reports"""
        if not self.reports["assets"]:
            return {}
        
        total_assets = 0
        all_assets = []
        
        for report in self.reports["assets"]:
            total_assets += report.get("total_active_hosts", 0)
            all_assets.extend(report.get("assets", []))
        
        open_services = {}
        os_distribution = {}
        
        for asset in all_assets:
            for port in asset.get("open_ports", []):
                open_services[port] = open_services.get(port, 0) + 1
            
            os = asset.get("os_guess", "unknown")
            os_distribution[os] = os_distribution.get(os, 0) + 1
        
        return {
            "total_assets": total_assets,
            "top_services": sorted(open_services.items(), key=lambda x: x[1], reverse=True)[:10],
            "os_distribution": os_distribution
        }
    
    def analyze_vulnerabilities(self) -> Dict:
        """Analyze vulnerability reports"""
        if not self.reports["vulnerabilities"]:
            return {}
        
        all_vulns = []
        for report in self.reports["vulnerabilities"]:
            all_vulns.extend(report.get("vulnerabilities", []))
        
        severity_count = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        vuln_types = {}
        
        for vuln in all_vulns:
            severity = vuln.get("severity", "UNKNOWN")
            if severity in severity_count:
                severity_count[severity] += 1
            
            vtype = vuln.get("type", "Unknown")
            vuln_types[vtype] = vuln_types.get(vtype, 0) + 1
        
        return {
            "total_vulnerabilities": len(all_vulns),
            "severity_distribution": severity_count,
            "vulnerability_types": vuln_types
        }
    
    def analyze_credentials(self) -> Dict:
        """Analyze credential audit reports"""
        if not self.reports["credentials"]:
            return {}
        
        total_accounts = 0
        weak_passwords = 0
        critical_issues = 0
        
        for report in self.reports["credentials"]:
            total_accounts += report.get("total_accounts", 0)
            weak_passwords += report.get("weak_passwords", 0)
            critical_issues += report.get("critical_passwords", 0)
        
        return {
            "total_accounts": total_accounts,
            "weak_passwords": weak_passwords,
            "critical_issues": critical_issues,
            "compliance_rate": ((total_accounts - weak_passwords) / total_accounts * 100) if total_accounts > 0 else 0
        }
    
    def generate_recommendations(self) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        vuln_analysis = self.aggregated_data.get("vulnerability_analysis", {})
        if vuln_analysis.get("severity_distribution", {}).get("HIGH", 0) > 0:
            recommendations.append("🔴 CRITICAL: Address HIGH severity vulnerabilities immediately")
        
        cred_analysis = self.aggregated_data.get("credential_analysis", {})
        if cred_analysis.get("critical_issues", 0) > 0:
            recommendations.append("🔴 CRITICAL: Force password reset for accounts with critical issues")
        
        if cred_analysis.get("compliance_rate", 100) < 80:
            recommendations.append("🟡 WARNING: Password compliance rate below 80% - enforce stronger policies")
        
        asset_analysis = self.aggregated_data.get("asset_analysis", {})
        if asset_analysis.get("top_services"):
            recommendations.append("ℹ️  INFO: Review exposed services and close unnecessary ports")
        
        recommendations.extend([
            "✅ RECOMMENDED: Implement regular security scanning schedule",
            "✅ RECOMMENDED: Enable multi-factor authentication for all accounts",
            "✅ RECOMMENDED: Deploy honeytokens for intrusion detection",
            "✅ RECOMMENDED: Conduct security awareness training"
        ])
        
        return recommendations
    
    def generate_html_report(self) -> Path:
        """Generate comprehensive HTML report"""
        report_file = Path(f"security_assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        
        asset_stats = self.aggregated_data.get("asset_analysis", {})
        vuln_stats = self.aggregated_data.get("vulnerability_analysis", {})
        cred_stats = self.aggregated_data.get("credential_analysis", {})
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Assessment Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }}
        .container {{ max-width: 1400px; margin: 20px auto; background: white; border-radius: 10px; box-shadow: 0 10px 40px rgba(0,0,0,0.3); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 10px 10px 0 0; }}
        .header h1 {{ margin: 0; font-size: 36px; }}
        .header p {{ margin: 10px 0 0 0; opacity: 0.9; }}
        .content {{ padding: 40px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0; }}
        .stat-card {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
        .stat-card.blue {{ background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); }}
        .stat-card.green {{ background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%); }}
        .stat-card.orange {{ background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); }}
        .stat-card h3 {{ margin: 0 0 10px 0; font-size: 16px; opacity: 0.9; }}
        .stat-card .value {{ font-size: 48px; font-weight: bold; margin: 10px 0; }}
        .section {{ margin: 40px 0; }}
        .section h2 {{ color: #667eea; border-bottom: 3px solid #667eea; padding-bottom: 10px; }}
        .recommendations {{ background: #f8f9fa; border-left: 4px solid #667eea; padding: 20px; border-radius: 5px; }}
        .recommendations li {{ margin: 10px 0; padding: 10px; background: white; border-radius: 5px; }}
        .critical {{ color: #dc3545; font-weight: bold; }}
        .warning {{ color: #ffc107; font-weight: bold; }}
        .info {{ color: #17a2b8; }}
        .success {{ color: #28a745; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #667eea; color: white; }}
        tr:hover {{ background: #f5f5f5; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Assessment Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Cerberus Agents Security Toolkit v1.0</p>
        </div>
        
        <div class="content">
            <div class="stats-grid">
                <div class="stat-card blue">
                    <h3>Assets Discovered</h3>
                    <div class="value">{asset_stats.get('total_assets', 0)}</div>
                </div>
                <div class="stat-card orange">
                    <h3>Vulnerabilities Found</h3>
                    <div class="value">{vuln_stats.get('total_vulnerabilities', 0)}</div>
                </div>
                <div class="stat-card">
                    <h3>Accounts Audited</h3>
                    <div class="value">{cred_stats.get('total_accounts', 0)}</div>
                </div>
                <div class="stat-card green">
                    <h3>Password Compliance</h3>
                    <div class="value">{cred_stats.get('compliance_rate', 0):.0f}%</div>
                </div>
            </div>
            
            <div class="section">
                <h2>📊 Vulnerability Summary</h2>
                <table>
                    <tr>
                        <th>Severity</th>
                        <th>Count</th>
                    </tr>
                    <tr>
                        <td class="critical">HIGH</td>
                        <td class="critical">{vuln_stats.get('severity_distribution', {}).get('HIGH', 0)}</td>
                    </tr>
                    <tr>
                        <td class="warning">MEDIUM</td>
                        <td class="warning">{vuln_stats.get('severity_distribution', {}).get('MEDIUM', 0)}</td>
                    </tr>
                    <tr>
                        <td class="info">LOW</td>
                        <td class="info">{vuln_stats.get('severity_distribution', {}).get('LOW', 0)}</td>
                    </tr>
                </table>
            </div>
            
            <div class="section">
                <h2>🔐 Credential Security</h2>
                <p><strong>Weak Passwords:</strong> {cred_stats.get('weak_passwords', 0)} / {cred_stats.get('total_accounts', 0)}</p>
                <p><strong>Critical Issues:</strong> <span class="critical">{cred_stats.get('critical_issues', 0)}</span></p>
            </div>
            
            <div class="section">
                <h2>💡 Recommendations</h2>
                <ul class="recommendations">
                    {''.join([f'<li>{rec}</li>' for rec in self.aggregated_data.get('recommendations', [])])}
                </ul>
            </div>
            
            <div class="section">
                <p style="text-align: center; color: #999;">
                    This report is confidential and should be handled according to security policies.
                </p>
            </div>
        </div>
    </div>
</body>
</html>"""
        
        with report_file.open("w") as f:
            f.write(html)
        
        return report_file
    
    def run(self):
        """Execute report aggregation"""
        logger.info("=" * 60)
        logger.info("🛡️  CERBERUS REPORT AGGREGATOR")
        logger.info("=" * 60)
        
        self.collect_reports()
        
        logger.info("\n📊 Analyzing data...")
        
        self.aggregated_data["asset_analysis"] = self.analyze_assets()
        self.aggregated_data["vulnerability_analysis"] = self.analyze_vulnerabilities()
        self.aggregated_data["credential_analysis"] = self.analyze_credentials()
        self.aggregated_data["recommendations"] = self.generate_recommendations()
        
        json_file = Path(f"aggregated_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with json_file.open("w") as f:
            json.dump(self.aggregated_data, f, indent=2)
        
        html_file = self.generate_html_report()
        
        logger.info("\n" + "=" * 60)
        logger.info("📊 AGGREGATION SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Assets: {self.aggregated_data['asset_analysis'].get('total_assets', 0)}")
        logger.info(f"Vulnerabilities: {self.aggregated_data['vulnerability_analysis'].get('total_vulnerabilities', 0)}")
        logger.info(f"Accounts: {self.aggregated_data['credential_analysis'].get('total_accounts', 0)}")
        logger.info(f"\n✅ Aggregation complete!")
        logger.info(f"📄 JSON report: {json_file.absolute()}")
        logger.info(f"📄 HTML report: {html_file.absolute()}")


def main():
    parser = argparse.ArgumentParser(description="Report Aggregator")
    parser.add_argument("--scan-dir", default=".", help="Directory containing scan reports")
    parser.add_argument('--authorized', action='store_true',
                       help='Confirm you have authorization to perform this action')
    args = parser.parse_args()
    
    aggregator = ReportAggregator(args.scan_dir)
    aggregator.run()


if __name__ == "__main__":
    main()
