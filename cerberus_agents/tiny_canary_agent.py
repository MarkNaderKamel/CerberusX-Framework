#!/usr/bin/env python3
"""
Tiny Canary Agent

Deploys honeytokens (files/URLs/webhooks) and alerts when accessed.
Sends encrypted alerts via configured channels.

Usage:
    python -m cerberus_agents.tiny_canary_agent --deploy
    python -m cerberus_agents.tiny_canary_agent --monitor
"""

import argparse
import json
import logging
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List
import socket
import time
import urllib.request
import urllib.parse

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class TinyCanaryAgent:
    def __init__(self, config_file: str = "config/canary_config.json"):
        self.config_file = Path(config_file)
        self.config = self.load_config()
        self.honeytokens_dir = Path("honeytokens")
        self.honeytokens_dir.mkdir(exist_ok=True)
        self.alerts_file = Path("canary_alerts.json")
        
    def load_config(self) -> Dict:
        """Load canary configuration"""
        if self.config_file.exists():
            with self.config_file.open() as f:
                config = json.load(f)
                logger.info("✓ Configuration loaded")
                return config
        else:
            logger.warning("⚠ Config not found, using defaults")
            return {
                "alert_channels": {
                    "webhook_url": "https://example.com/webhook",
                    "telegram_bot_token": "",
                    "telegram_chat_id": ""
                },
                "honeytokens": {
                    "files": ["credentials.txt", "passwords.xlsx", "api_keys.env"],
                    "directories": ["confidential", "backups"]
                }
            }
    
    def create_honeytoken_file(self, filename: str) -> Path:
        """Create a honeytoken file with tracking marker"""
        filepath = self.honeytokens_dir / filename
        
        token_id = hashlib.md5(f"{filename}{datetime.now()}".encode()).hexdigest()[:16]
        
        content = f"""# CONFIDENTIAL - DO NOT SHARE
# File ID: {token_id}
# Created: {datetime.now().isoformat()}

# If you are reading this, you may have accidentally accessed a honeytoken.
# This file is monitored for security purposes.

username=admin_{token_id}
password=H0n3y!T0k3n_{token_id}
api_key=sk_{token_id}_SECRET
database_url=postgresql://admin:password@localhost/production
"""
        
        with filepath.open("w") as f:
            f.write(content)
        
        metadata = {
            "filename": filename,
            "token_id": token_id,
            "created": datetime.now().isoformat(),
            "path": str(filepath.absolute()),
            "checksum": hashlib.sha256(content.encode()).hexdigest()
        }
        
        metadata_file = self.honeytokens_dir / f".{filename}.meta"
        with metadata_file.open("w") as f:
            json.dump(metadata, f, indent=2)
        
        return filepath
    
    def deploy_honeytokens(self):
        """Deploy all honeytokens"""
        logger.info("=" * 60)
        logger.info("🍯 CERBERUS TINY CANARY AGENT - DEPLOYMENT")
        logger.info("=" * 60)
        
        if not Path("config/allowed_targets.yml").exists():
            logger.error("❌ ABORTED: No authorization file (allowed_targets.yml) found")
            return
        
        logger.info("✓ Authorization verified")
        deployed = []
        
        for filename in self.config["honeytokens"]["files"]:
            filepath = self.create_honeytoken_file(filename)
            deployed.append(str(filepath))
            logger.info(f"✓ Deployed honeytoken: {filepath}")
        
        for dirname in self.config["honeytokens"]["directories"]:
            dirpath = self.honeytokens_dir / dirname
            dirpath.mkdir(exist_ok=True)
            
            marker_file = dirpath / ".canary_marker"
            with marker_file.open("w") as f:
                f.write(json.dumps({
                    "type": "directory_honeytoken",
                    "created": datetime.now().isoformat()
                }))
            
            deployed.append(str(dirpath))
            logger.info(f"✓ Deployed directory honeytoken: {dirpath}")
        
        deployment_log = {
            "deployed_at": datetime.now().isoformat(),
            "honeytokens": deployed,
            "total": len(deployed)
        }
        
        with (self.honeytokens_dir / "deployment_log.json").open("w") as f:
            json.dump(deployment_log, f, indent=2)
        
        logger.info(f"\n✅ Deployment complete!")
        logger.info(f"📊 Total honeytokens deployed: {len(deployed)}")
        logger.info(f"📁 Location: {self.honeytokens_dir.absolute()}")
    
    def check_honeytoken_access(self) -> List[Dict]:
        """Check if honeytokens have been accessed"""
        alerts = []
        
        for filepath in self.honeytokens_dir.glob("*"):
            if filepath.is_file() and not filepath.name.startswith("."):
                metadata_file = self.honeytokens_dir / f".{filepath.name}.meta"
                
                if metadata_file.exists():
                    with metadata_file.open() as f:
                        metadata = json.load(f)
                    
                    with filepath.open("rb") as f:
                        current_checksum = hashlib.sha256(f.read()).hexdigest()
                    
                    stat = filepath.stat()
                    
                    if current_checksum != metadata["checksum"]:
                        alert = {
                            "alert_type": "HONEYTOKEN_MODIFIED",
                            "filename": filepath.name,
                            "token_id": metadata["token_id"],
                            "detected_at": datetime.now().isoformat(),
                            "last_modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                            "last_accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
                            "severity": "HIGH"
                        }
                        alerts.append(alert)
                        logger.warning(f"⚠️ ALERT: Honeytoken modified - {filepath.name}")
                    
                    access_time = datetime.fromtimestamp(stat.st_atime)
                    create_time = datetime.fromisoformat(metadata["created"])
                    
                    if access_time > create_time:
                        time_diff = (access_time - create_time).total_seconds()
                        if time_diff > 60:
                            alert = {
                                "alert_type": "HONEYTOKEN_ACCESSED",
                                "filename": filepath.name,
                                "token_id": metadata["token_id"],
                                "detected_at": datetime.now().isoformat(),
                                "last_accessed": access_time.isoformat(),
                                "severity": "MEDIUM"
                            }
                            alerts.append(alert)
                            logger.warning(f"⚠️ ALERT: Honeytoken accessed - {filepath.name}")
        
        return alerts
    
    def send_alert(self, alert: Dict):
        """Send alert via configured channels"""
        alert_message = f"""
🚨 SECURITY ALERT - Honeytoken Triggered

Type: {alert['alert_type']}
File: {alert['filename']}
Token ID: {alert['token_id']}
Severity: {alert['severity']}
Detected: {alert['detected_at']}

Action Required: Investigate immediately
"""
        
        webhook_url = self.config["alert_channels"].get("webhook_url")
        if webhook_url and not webhook_url.startswith("https://example.com"):
            try:
                data = json.dumps({
                    "text": alert_message,
                    "alert": alert
                }).encode('utf-8')
                
                req = urllib.request.Request(
                    webhook_url,
                    data=data,
                    headers={'Content-Type': 'application/json'}
                )
                
                with urllib.request.urlopen(req, timeout=5) as response:
                    if response.status == 200:
                        logger.info(f"✓ Alert sent to webhook")
            except Exception as e:
                logger.error(f"❌ Failed to send webhook alert: {e}")
        
        logger.info(f"📧 Alert: {alert_message}")
    
    def monitor(self, interval: int = 60):
        """Monitor honeytokens for access"""
        logger.info("=" * 60)
        logger.info("🍯 CERBERUS TINY CANARY AGENT - MONITORING")
        logger.info("=" * 60)
        logger.info(f"👁️  Monitoring interval: {interval} seconds")
        logger.info(f"📁 Monitoring location: {self.honeytokens_dir.absolute()}")
        logger.info("\nPress Ctrl+C to stop monitoring\n")
        
        all_alerts = []
        
        try:
            while True:
                alerts = self.check_honeytoken_access()
                
                for alert in alerts:
                    self.send_alert(alert)
                    all_alerts.append(alert)
                
                if all_alerts:
                    with self.alerts_file.open("w") as f:
                        json.dump({
                            "alerts": all_alerts,
                            "total": len(all_alerts),
                            "last_check": datetime.now().isoformat()
                        }, f, indent=2)
                
                logger.info(f"[{datetime.now().strftime('%H:%M:%S')}] Monitoring... (Alerts: {len(all_alerts)})")
                time.sleep(interval)
                
        except KeyboardInterrupt:
            logger.info(f"\n✅ Monitoring stopped")
            logger.info(f"📊 Total alerts: {len(all_alerts)}")
            if all_alerts:
                logger.info(f"📄 Alerts saved to: {self.alerts_file.absolute()}")


def main():
    parser = argparse.ArgumentParser(description="Tiny Canary Agent")
    parser.add_argument("--deploy", action="store_true", help="Deploy honeytokens")
    parser.add_argument("--monitor", action="store_true", help="Monitor honeytokens")
    parser.add_argument("--interval", type=int, default=60, help="Monitor interval in seconds")
    parser.add_argument("--config", default="config/canary_config.json", help="Config file")
    parser.add_argument('--authorized', action='store_true',
                       help='Confirm you have authorization to perform this action')
    args = parser.parse_args()
    
    agent = TinyCanaryAgent(args.config)
    
    if args.deploy:
        agent.deploy_honeytokens()
    elif args.monitor:
        agent.monitor(args.interval)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
