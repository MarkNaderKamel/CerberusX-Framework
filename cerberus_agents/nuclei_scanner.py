#!/usr/bin/env python3
"""
Nuclei Scanner - Template-based Vulnerability Scanner
Production-ready integration with ProjectDiscovery's Nuclei
Supports 10,000+ community templates for comprehensive vulnerability detection
"""

import subprocess
import json
import logging
import argparse
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional
import yaml

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class NucleiScanner:
    """
    Production Nuclei scanner integration
    Leverages ProjectDiscovery's template-based vulnerability detection
    """
    
    def __init__(self, templates_dir: Optional[str] = None):
        self.templates_dir = templates_dir or str(Path.home() / "nuclei-templates")
        self.results = []
        
    def check_installation(self) -> bool:
        """Check if nuclei is installed"""
        try:
            result = subprocess.run(['nuclei', '-version'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                logger.info(f"Nuclei installed: {result.stdout.strip()}")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        logger.error("Nuclei not installed. Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        return False
    
    def update_templates(self) -> bool:
        """Update nuclei templates to latest version"""
        logger.info("Updating Nuclei templates...")
        try:
            result = subprocess.run(['nuclei', '-update-templates'], 
                                  capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                logger.info("Templates updated successfully")
                return True
            else:
                logger.error(f"Template update failed: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Error updating templates: {e}")
            return False
    
    def scan_target(self, target: str, severity: Optional[List[str]] = None,
                   tags: Optional[List[str]] = None, custom_templates: Optional[List[str]] = None,
                   output_file: Optional[str] = None, rate_limit: int = 150) -> Dict:
        """
        Scan target with Nuclei
        
        Args:
            target: Target URL or host
            severity: Filter by severity (critical, high, medium, low, info)
            tags: Filter by tags (cve, exposure, misconfiguration, etc.)
            custom_templates: List of custom template paths
            output_file: Save results to file
            rate_limit: Requests per second limit
        """
        if not self.check_installation():
            return {"error": "Nuclei not installed"}
        
        cmd = [
            'nuclei',
            '-target', target,
            '-json',
            '-rate-limit', str(rate_limit),
            '-severity', ','.join(severity) if severity else 'critical,high,medium,low',
            '-stats',
            '-silent'
        ]
        
        if tags:
            cmd.extend(['-tags', ','.join(tags)])
        
        if custom_templates:
            for template in custom_templates:
                cmd.extend(['-t', template])
        
        logger.info(f"Scanning {target} with Nuclei...")
        logger.info(f"Command: {' '.join(cmd)}")
        
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE, text=True)
            
            findings = []
            if process.stdout:
                for line in process.stdout:
                    try:
                        finding = json.loads(line.strip())
                        findings.append(finding)
                        logger.info(f"[{finding.get('info', {}).get('severity', 'UNKNOWN')}] "
                                  f"{finding.get('info', {}).get('name', 'Unknown')} - {finding.get('matched-at', 'N/A')}")
                    except json.JSONDecodeError:
                        continue
            
            process.wait(timeout=600)
            
            if output_file:
                self._save_results(findings, output_file)
            
            self.results = findings
            return {
                "target": target,
                "findings_count": len(findings),
                "findings": findings,
                "severity_breakdown": self._analyze_severity(findings)
            }
            
        except subprocess.TimeoutExpired:
            logger.error("Scan timeout exceeded")
            return {"error": "Scan timeout"}
        except Exception as e:
            logger.error(f"Scan error: {e}")
            return {"error": str(e)}
    
    def scan_multiple_targets(self, targets_file: str, **kwargs) -> Dict:
        """Scan multiple targets from file"""
        if not os.path.exists(targets_file):
            return {"error": f"Targets file not found: {targets_file}"}
        
        cmd = [
            'nuclei',
            '-list', targets_file,
            '-json',
            '-stats'
        ]
        
        severity = kwargs.get('severity')
        if severity:
            cmd.extend(['-severity', ','.join(severity)])
        
        logger.info(f"Scanning targets from {targets_file}...")
        
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE, text=True)
            
            findings = []
            if process.stdout:
                for line in process.stdout:
                    try:
                        finding = json.loads(line.strip())
                        findings.append(finding)
                    except json.JSONDecodeError:
                        continue
            
            process.wait(timeout=1800)
            
            return {
                "targets_file": targets_file,
                "findings_count": len(findings),
                "findings": findings,
                "severity_breakdown": self._analyze_severity(findings)
            }
            
        except Exception as e:
            logger.error(f"Multi-target scan error: {e}")
            return {"error": str(e)}
    
    def scan_with_workflow(self, target: str, workflow: str) -> Dict:
        """
        Scan with predefined workflow
        
        Workflows: dns, ssl, network, exposed-panels, vulnerabilities, etc.
        """
        cmd = [
            'nuclei',
            '-target', target,
            '-w', workflow,
            '-json',
            '-stats'
        ]
        
        logger.info(f"Running workflow '{workflow}' on {target}...")
        
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE, text=True)
            
            findings = []
            if process.stdout:
                for line in process.stdout:
                    try:
                        finding = json.loads(line.strip())
                        findings.append(finding)
                    except json.JSONDecodeError:
                        continue
            
            process.wait(timeout=300)
            
            return {
                "target": target,
                "workflow": workflow,
                "findings_count": len(findings),
                "findings": findings
            }
            
        except Exception as e:
            logger.error(f"Workflow scan error: {e}")
            return {"error": str(e)}
    
    def _analyze_severity(self, findings: List[Dict]) -> Dict:
        """Analyze severity distribution"""
        severity_count = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for finding in findings:
            severity = finding.get('info', {}).get('severity', 'info').lower()
            if severity in severity_count:
                severity_count[severity] += 1
        
        return severity_count
    
    def _save_results(self, findings: List[Dict], output_file: str):
        """Save results to file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(findings, f, indent=2)
            logger.info(f"Results saved to {output_file}")
        except Exception as e:
            logger.error(f"Error saving results: {e}")
    
    def generate_report(self, output_format: str = 'html') -> str:
        """Generate human-readable report"""
        if not self.results:
            return "No scan results available"
        
        if output_format == 'html':
            return self._generate_html_report()
        else:
            return self._generate_text_report()
    
    def _generate_html_report(self) -> str:
        """Generate HTML report"""
        severity_breakdown = self._analyze_severity(self.results)
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Nuclei Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .critical {{ color: #d32f2f; }}
                .high {{ color: #f57c00; }}
                .medium {{ color: #fbc02d; }}
                .low {{ color: #388e3c; }}
                .info {{ color: #1976d2; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #333; color: white; }}
            </style>
        </head>
        <body>
            <h1>Nuclei Vulnerability Scan Report</h1>
            <h2>Summary</h2>
            <p>Total Findings: {len(self.results)}</p>
            <ul>
                <li class="critical">Critical: {severity_breakdown['critical']}</li>
                <li class="high">High: {severity_breakdown['high']}</li>
                <li class="medium">Medium: {severity_breakdown['medium']}</li>
                <li class="low">Low: {severity_breakdown['low']}</li>
                <li class="info">Info: {severity_breakdown['info']}</li>
            </ul>
            
            <h2>Detailed Findings</h2>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Template</th>
                    <th>Matched At</th>
                    <th>Description</th>
                </tr>
        """
        
        for finding in self.results:
            info = finding.get('info', {})
            severity = info.get('severity', 'info').lower()
            name = info.get('name', 'Unknown')
            matched_at = finding.get('matched-at', 'N/A')
            description = info.get('description', 'No description')
            
            html += f"""
                <tr>
                    <td class="{severity}">{severity.upper()}</td>
                    <td>{name}</td>
                    <td>{matched_at}</td>
                    <td>{description}</td>
                </tr>
            """
        
        html += """
            </table>
        </body>
        </html>
        """
        
        return html
    
    def _generate_text_report(self) -> str:
        """Generate text report"""
        severity_breakdown = self._analyze_severity(self.results)
        
        report = "=" * 80 + "\n"
        report += "NUCLEI VULNERABILITY SCAN REPORT\n"
        report += "=" * 80 + "\n\n"
        report += f"Total Findings: {len(self.results)}\n\n"
        report += "SEVERITY BREAKDOWN:\n"
        report += f"  Critical: {severity_breakdown['critical']}\n"
        report += f"  High:     {severity_breakdown['high']}\n"
        report += f"  Medium:   {severity_breakdown['medium']}\n"
        report += f"  Low:      {severity_breakdown['low']}\n"
        report += f"  Info:     {severity_breakdown['info']}\n\n"
        report += "=" * 80 + "\n"
        report += "DETAILED FINDINGS\n"
        report += "=" * 80 + "\n\n"
        
        for i, finding in enumerate(self.results, 1):
            info = finding.get('info', {})
            report += f"{i}. [{info.get('severity', 'INFO').upper()}] {info.get('name', 'Unknown')}\n"
            report += f"   Matched At: {finding.get('matched-at', 'N/A')}\n"
            report += f"   Description: {info.get('description', 'No description')}\n"
            report += f"   Tags: {', '.join(info.get('tags', []))}\n\n"
        
        return report


def main():
    parser = argparse.ArgumentParser(description="Nuclei Vulnerability Scanner")
    parser.add_argument('--target', help='Target URL or host')
    parser.add_argument('--targets-file', help='File containing list of targets')
    parser.add_argument('--severity', nargs='+', 
                       choices=['critical', 'high', 'medium', 'low', 'info'],
                       help='Filter by severity')
    parser.add_argument('--tags', nargs='+', help='Filter by tags')
    parser.add_argument('--workflow', help='Use predefined workflow')
    parser.add_argument('--update', action='store_true', help='Update templates')
    parser.add_argument('--output', help='Output file for results')
    parser.add_argument('--report', help='Generate HTML report file')
    parser.add_argument('--authorized', action='store_true',
                       help='Confirm you have authorization to perform this action')
    args = parser.parse_args()
    
    scanner = NucleiScanner()
    
    if args.update:
        scanner.update_templates()
        return
    
    if not args.target and not args.targets_file:
        print("Error: Provide --target or --targets-file")
        print("\nInstallation Instructions:")
        print("  1. Install Go: https://golang.org/dl/")
        print("  2. Install Nuclei: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        print("  3. Add $HOME/go/bin to PATH")
        print("  4. Run: nuclei -update-templates")
        return
    
    if args.workflow:
        results = scanner.scan_with_workflow(args.target, args.workflow)
    elif args.targets_file:
        results = scanner.scan_multiple_targets(args.targets_file, severity=args.severity)
    else:
        results = scanner.scan_target(args.target, severity=args.severity, 
                                     tags=args.tags, output_file=args.output)
    
    if 'error' in results:
        logger.error(f"Scan failed: {results['error']}")
        return
    
    print(f"\n{'='*80}")
    print("SCAN SUMMARY")
    print(f"{'='*80}")
    print(f"Total Findings: {results['findings_count']}")
    
    if 'severity_breakdown' in results:
        print("\nSeverity Breakdown:")
        for severity, count in results['severity_breakdown'].items():
            print(f"  {severity.capitalize()}: {count}")
    
    if args.report:
        html_report = scanner.generate_report('html')
        with open(args.report, 'w') as f:
            f.write(html_report)
        print(f"\nHTML report saved to: {args.report}")
    
    print(scanner.generate_report('text'))


if __name__ == "__main__":
    main()
