#!/usr/bin/env python3
"""
GoPhish - Open-Source Phishing Framework
Campaign management, email templates, and landing pages
Production-ready phishing framework for security awareness training
"""

import subprocess
import json
import logging
import argparse
import os
import sys
import requests
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class GoPhishManager:
    """
    GoPhish API integration for phishing campaign management
    """
    
    def __init__(self, api_url: str = 'https://localhost:3333', api_key: Optional[str] = None):
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key or os.getenv('GOPHISH_API_KEY', '')
        self.headers = {'Authorization': f'Bearer {self.api_key}'}
        self.gophish_dir = str(Path.home() / "gophish")
        
    def check_installation(self) -> bool:
        """Check if GoPhish is running"""
        # First check if binary exists
        gophish_bin = Path(self.gophish_dir) / "gophish"
        if gophish_bin.exists():
            logger.info(f"✅ GoPhish binary found at: {gophish_bin}")
        
        # Check if service is running
        try:
            response = requests.get(f'{self.api_url}/api/', 
                                   headers=self.headers, verify=False, timeout=5)
            if response.status_code == 200:
                logger.info("✅ GoPhish service is running")
                return True
        except requests.RequestException:
            pass
        
        if gophish_bin.exists():
            logger.warning("⚠️  GoPhish binary found but service not running - start it with: cd ~/gophish && ./gophish")
        else:
            logger.warning("⚠️  GoPhish not installed - use --install for installation instructions")
        return False
    
    def install_gophish(self, install_dir: str = '/opt/gophish') -> Dict:
        """
        Installation instructions for GoPhish
        """
        return {
            'installation': 'manual',
            'steps': [
                f'1. Download from https://github.com/gophish/gophish/releases',
                f'2. Extract to {install_dir}',
                f'3. Edit config.json for your environment',
                f'4. Run: cd {install_dir} && sudo ./gophish',
                f'5. Default admin panel: https://localhost:3333',
                f'6. Default phishing server: http://localhost:80',
                f'7. Get API key from Settings in admin panel'
            ],
            'note': 'Change default password on first login!'
        }
    
    def create_smtp_profile(self, name: str, host: str, port: int,
                           username: str, password: str, from_address: str) -> Dict:
        """
        Create SMTP sending profile
        """
        if not self.check_installation():
            return {"error": "GoPhish not running"}
        
        profile = {
            'name': name,
            'host': f'{host}:{port}',
            'username': username,
            'password': password,
            'from_address': from_address,
            'ignore_cert_errors': True
        }
        
        try:
            response = requests.post(
                f'{self.api_url}/api/smtp/',
                json=profile,
                headers=self.headers,
                verify=False
            )
            
            if response.status_code == 201:
                logger.info(f"SMTP profile created: {name}")
                return response.json()
            else:
                logger.error(f"Failed to create SMTP profile: {response.text}")
                return {'error': response.text}
                
        except requests.RequestException as e:
            logger.error(f"Error: {e}")
            return {'error': str(e)}
    
    def create_landing_page(self, name: str, html: str, 
                           capture_credentials: bool = True,
                           capture_passwords: bool = False,
                           redirect_url: str = '') -> Dict:
        """
        Create phishing landing page
        """
        if not self.check_installation():
            return {"error": "GoPhish not running"}
        
        page = {
            'name': name,
            'html': html,
            'capture_credentials': capture_credentials,
            'capture_passwords': capture_passwords,
            'redirect_url': redirect_url
        }
        
        try:
            response = requests.post(
                f'{self.api_url}/api/pages/',
                json=page,
                headers=self.headers,
                verify=False
            )
            
            if response.status_code == 201:
                logger.info(f"Landing page created: {name}")
                return response.json()
            else:
                return {'error': response.text}
                
        except requests.RequestException as e:
            return {'error': str(e)}
    
    def create_email_template(self, name: str, subject: str, 
                             text: str, html: str,
                             attachments: Optional[List[Dict]] = None) -> Dict:
        """
        Create email template
        """
        if not self.check_installation():
            return {"error": "GoPhish not running"}
        
        template = {
            'name': name,
            'subject': subject,
            'text': text,
            'html': html,
            'attachments': attachments or []
        }
        
        try:
            response = requests.post(
                f'{self.api_url}/api/templates/',
                json=template,
                headers=self.headers,
                verify=False
            )
            
            if response.status_code == 201:
                logger.info(f"Email template created: {name}")
                return response.json()
            else:
                return {'error': response.text}
                
        except requests.RequestException as e:
            return {'error': str(e)}
    
    def create_user_group(self, name: str, targets: List[Dict]) -> Dict:
        """
        Create target user group
        
        targets format: [{'email': 'user@example.com', 'first_name': 'John', 'last_name': 'Doe'}]
        """
        if not self.check_installation():
            return {"error": "GoPhish not running"}
        
        group = {
            'name': name,
            'targets': targets
        }
        
        try:
            response = requests.post(
                f'{self.api_url}/api/groups/',
                json=group,
                headers=self.headers,
                verify=False
            )
            
            if response.status_code == 201:
                logger.info(f"User group created: {name} ({len(targets)} targets)")
                return response.json()
            else:
                return {'error': response.text}
                
        except requests.RequestException as e:
            return {'error': str(e)}
    
    def launch_campaign(self, name: str, template_id: int, page_id: int,
                       smtp_id: int, group_id: int, url: str,
                       launch_date: Optional[str] = None) -> Dict:
        """
        Launch phishing campaign
        
        Args:
            name: Campaign name
            template_id: Email template ID
            page_id: Landing page ID
            smtp_id: SMTP profile ID
            group_id: Target group ID
            url: Phishing URL (e.g., http://phish.example.com)
            launch_date: ISO format datetime (immediate if None)
        """
        if not self.check_installation():
            return {"error": "GoPhish not running"}
        
        campaign = {
            'name': name,
            'template': {'id': template_id},
            'page': {'id': page_id},
            'smtp': {'id': smtp_id},
            'groups': [{'id': group_id}],
            'url': url,
            'launch_date': launch_date or datetime.now().isoformat()
        }
        
        logger.warning(f"⚠️  Launching phishing campaign: {name}")
        
        try:
            response = requests.post(
                f'{self.api_url}/api/campaigns/',
                json=campaign,
                headers=self.headers,
                verify=False
            )
            
            if response.status_code == 201:
                logger.info(f"Campaign launched: {name}")
                return response.json()
            else:
                logger.error(f"Failed to launch campaign: {response.text}")
                return {'error': response.text}
                
        except requests.RequestException as e:
            logger.error(f"Error: {e}")
            return {'error': str(e)}
    
    def get_campaign_results(self, campaign_id: int) -> Dict:
        """Get campaign results and statistics"""
        try:
            response = requests.get(
                f'{self.api_url}/api/campaigns/{campaign_id}',
                headers=self.headers,
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                
                stats = {
                    'name': data.get('name'),
                    'status': data.get('status'),
                    'created_date': data.get('created_date'),
                    'launch_date': data.get('launch_date'),
                    'timeline': data.get('timeline', []),
                    'results': data.get('results', []),
                    'summary': self._calculate_stats(data)
                }
                
                return stats
            else:
                return {'error': response.text}
                
        except requests.RequestException as e:
            return {'error': str(e)}
    
    def _calculate_stats(self, campaign_data: Dict) -> Dict:
        """Calculate campaign statistics"""
        results = campaign_data.get('results', [])
        total = len(results)
        
        if total == 0:
            return {'total': 0}
        
        stats = {
            'total_targets': total,
            'emails_sent': sum(1 for r in results if r.get('status') == 'Email Sent'),
            'emails_opened': sum(1 for r in results if r.get('status') == 'Email Opened'),
            'links_clicked': sum(1 for r in results if r.get('status') == 'Clicked Link'),
            'data_submitted': sum(1 for r in results if r.get('status') == 'Submitted Data'),
            'reported': sum(1 for r in results if r.get('status') == 'Email Reported')
        }
        
        stats['open_rate'] = float((stats['emails_opened'] / total * 100)) if total > 0 else 0.0
        stats['click_rate'] = float((stats['links_clicked'] / total * 100)) if total > 0 else 0.0
        stats['submission_rate'] = float((stats['data_submitted'] / total * 100)) if total > 0 else 0.0
        
        return stats
    
    def export_campaign_data(self, campaign_id: int, output_file: str) -> bool:
        """Export campaign results to file"""
        results = self.get_campaign_results(campaign_id)
        
        if 'error' in results:
            logger.error(f"Failed to export: {results['error']}")
            return False
        
        try:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            logger.info(f"Campaign data exported to: {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Export error: {e}")
            return False


def generate_sample_templates() -> Dict[str, Dict]:
    """Generate sample phishing templates"""
    templates = {
        'microsoft_password_reset': {
            'subject': 'Microsoft Account - Password Expiration Alert',
            'html': '''
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <img src="{{.Tracker}}" style="display:none;">
        <h2>Microsoft Account Security Alert</h2>
        <p>Dear {{.FirstName}},</p>
        <p>Your password will expire in 24 hours. Please reset it immediately to avoid account lockout.</p>
        <p><a href="{{.URL}}" style="background-color: #0078D4; color: white; padding: 10px 20px; text-decoration: none; display: inline-block;">Reset Password</a></p>
        <p>If you did not request this, please ignore this email.</p>
        <p>Best regards,<br>Microsoft Security Team</p>
    </div>
</body>
</html>
            '''
        },
        'it_survey': {
            'subject': 'IT Department - Annual Security Survey',
            'html': '''
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif;">
    <img src="{{.Tracker}}" style="display:none;">
    <h2>IT Security Awareness Survey</h2>
    <p>Hi {{.FirstName}},</p>
    <p>Please complete our brief security awareness survey.</p>
    <p><a href="{{.URL}}">Take Survey (5 minutes)</a></p>
    <p>Thank you,<br>IT Department</p>
</body>
</html>
            '''
        }
    }
    
    return templates


def main():
    parser = argparse.ArgumentParser(description="GoPhish Campaign Manager")
    parser.add_argument('--api-url', default='https://localhost:3333',
                       help='GoPhish API URL')
    parser.add_argument('--api-key', help='API key (or set GOPHISH_API_KEY env var)')
    parser.add_argument('--install', action='store_true', help='Show installation instructions')
    parser.add_argument('--create-campaign', action='store_true', help='Create full campaign')
    parser.add_argument('--campaign-name', help='Campaign name')
    parser.add_argument('--targets-csv', help='CSV file with targets')
    parser.add_argument('--get-results', type=int, help='Get campaign results by ID')
    parser.add_argument('--export', help='Export campaign results to file')
    
    args = parser.parse_args()
    
    gophish = GoPhishManager(api_url=args.api_url, api_key=args.api_key)
    
    if args.install:
        instructions = gophish.install_gophish()
        print("\n📥 GoPhish Installation Instructions:")
        for step in instructions['steps']:
            print(f"   {step}")
        print(f"\n⚠️  {instructions['note']}")
        return
    
    if args.get_results:
        results = gophish.get_campaign_results(args.get_results)
        
        if 'error' not in results:
            print(f"\n{'='*80}")
            print(f"CAMPAIGN: {results['name']}")
            print(f"Status: {results['status']}")
            print(f"{'='*80}\n")
            
            summary = results.get('summary', {})
            print(f"Total Targets: {summary.get('total_targets', 0)}")
            print(f"Emails Sent: {summary.get('emails_sent', 0)}")
            print(f"Opened: {summary.get('emails_opened', 0)} ({summary.get('open_rate', 0):.1f}%)")
            print(f"Clicked: {summary.get('links_clicked', 0)} ({summary.get('click_rate', 0):.1f}%)")
            print(f"Submitted Data: {summary.get('data_submitted', 0)} ({summary.get('submission_rate', 0):.1f}%)")
            print(f"Reported: {summary.get('reported', 0)}")
            
            if args.export:
                gophish.export_campaign_data(args.get_results, args.export)
        else:
            print(f"Error: {results['error']}")
        
        return
    
    print("\n🎣 GoPhish - Phishing Campaign Framework")
    print("\n⚠️  LEGAL WARNING:")
    print("  - Requires explicit authorization for security awareness training")
    print("  - Unauthorized phishing is illegal")
    print("  - Ensure proper approvals before launching campaigns")
    print("\n📥 Installation:")
    print("  python cerberus_agents/gophish_campaigns.py --install")
    print("\n📚 Resources:")
    print("  https://github.com/gophish/gophish")
    print("  https://docs.getgophish.com/")


if __name__ == "__main__":
    # Disable SSL warnings for self-signed certificates
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    main()
