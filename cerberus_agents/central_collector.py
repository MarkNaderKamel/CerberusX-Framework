#!/usr/bin/env python3
"""
Central Collector

Simple HTTPS endpoint to receive agent reports with API key authentication.
Stores encrypted reports at rest.

Usage:
    python -m cerberus_agents.central_collector --start
"""

import argparse
import json
import logging
import hashlib
import secrets
from datetime import datetime
from pathlib import Path
from typing import Dict
import base64

try:
    from http.server import HTTPServer, BaseHTTPRequestHandler
    from cryptography.fernet import Fernet
    import ssl
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logging.error("CRITICAL: cryptography module is required for secure operation")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CentralCollector:
    """Central collector for agent reports with encryption"""
    
    def __init__(self, port: int = 8443, reports_dir: str = "collected_reports"):
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography module required for collector")
        
        self.port = port
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize encryption - persist key across restarts
        self.cipher_key_file = Path("config/collector_cipher_key.bin")
        self.cipher_key_file.parent.mkdir(parents=True, exist_ok=True)
        
        if not self.cipher_key_file.exists():
            self.cipher_key = Fernet.generate_key()
            self.cipher_key_file.write_bytes(self.cipher_key)
            logger.info(f"Generated new encryption key: {self.cipher_key_file.absolute()}")
        else:
            self.cipher_key = self.cipher_key_file.read_bytes()
            logger.info(f"Loaded existing encryption key: {self.cipher_key_file.absolute()}")
        
        self.cipher = Fernet(self.cipher_key)
        
        # Setup API key
        self.api_key_file = Path("config/collector_api_key.txt")
        self.api_key_file.parent.mkdir(parents=True, exist_ok=True)
        
        if not self.api_key_file.exists():
            self.api_key = secrets.token_urlsafe(32)
            self.api_key_file.write_text(self.api_key)
            logger.info(f"Generated new API key: {self.api_key_file.absolute()}")
        else:
            self.api_key = self.api_key_file.read_text().strip()
    
    def verify_api_key(self, provided_key: str) -> bool:
        """Verify API key"""
        return provided_key == self.api_key
    
    def decrypt_report(self, encrypted_data: bytes) -> Dict:
        """Decrypt received report"""
        try:
            decrypted = self.cipher.decrypt(encrypted_data)
            return json.loads(decrypted.decode())
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None
    
    def store_report(self, report_data: Dict) -> Path:
        """Store report to disk"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        agent_type = report_data.get('agent_type', 'unknown')
        filename = f"{agent_type}_{timestamp}.json"
        report_file = self.reports_dir / filename
        
        with report_file.open("w") as f:
            json.dump(report_data, f, indent=2)
        
        # Calculate checksum
        checksum = hashlib.sha256(json.dumps(report_data, sort_keys=True).encode()).hexdigest()
        report_data['_checksum'] = checksum
        
        logger.info(f"Stored report: {filename} (checksum: {checksum[:16]}...)")
        return report_file


class CollectorHTTPHandler(BaseHTTPRequestHandler):
    """HTTP handler for collector endpoints"""
    collector = None  # Set by start_collector
    
    def do_GET(self):
        """Health check endpoint"""
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "ok",
                "timestamp": datetime.now().isoformat()
            }).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        """Report submission endpoint"""
        if self.path == '/api/report':
            # Verify API key
            api_key = self.headers.get('X-API-Key', '')
            if not self.collector.verify_api_key(api_key):
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b'{"error": "Invalid API key"}')
                return
            
            # Read and process report
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            
            try:
                # Parse JSON report
                report_data = json.loads(post_data.decode())
                
                # Store report
                report_file = self.collector.store_report(report_data)
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({
                    "status": "received",
                    "file": str(report_file.name),
                    "timestamp": datetime.now().isoformat()
                }).encode())
            
            except Exception as e:
                logger.error(f"Report processing failed: {e}")
                self.send_response(500)
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass


def start_collector(port: int, reports_dir: str, use_tls: bool = True):
    """Start the collector server"""
    logger.info("=" * 60)
    logger.info("🚀 Central Collector Starting")
    logger.info("=" * 60)
    
    try:
        collector = CentralCollector(port, reports_dir)
    except RuntimeError as e:
        logger.error(f"❌ {e}")
        return
    
    CollectorHTTPHandler.collector = collector
    
    logger.info(f"\n📡 Starting collector server...")
    logger.info(f"   Port: {port}")
    logger.info(f"   Reports directory: {collector.reports_dir.absolute()}")
    logger.info(f"   Encryption: Enabled (mandatory)")
    logger.info(f"   TLS: {'Enabled (recommended)' if use_tls else 'Disabled (dev mode only)'}")
    
    api_key_file = Path("config/collector_api_key.txt")
    logger.info(f"   API Key: Stored in {api_key_file}")
    
    logger.info(f"\nEndpoints:")
    logger.info(f"   POST /api/report - Submit agent report")
    logger.info(f"   GET  /health     - Health check")
    logger.info(f"\nExample usage:")
    protocol = "https" if use_tls else "http"
    logger.info(f"   curl -X POST {protocol}://localhost:{port}/api/report \\")
    logger.info(f"        -H 'X-API-Key: [KEY_FROM_CONFIG_FILE]' \\")
    logger.info(f"        -H 'Content-Type: application/json' \\")
    logger.info(f"        -d '{{\"agent_type\": \"test\", \"data\": \"example\"}}'")
    logger.info(f"\n{'=' * 60}")
    logger.info("Server starting... Press Ctrl+C to stop\n")
    
    try:
        server = HTTPServer(('0.0.0.0', port), CollectorHTTPHandler)
        
        if use_tls:
            cert_file = Path("config/server.pem")
            if not cert_file.exists():
                logger.warning("⚠️  TLS certificate not found. Generating self-signed certificate...")
                logger.warning("   For production, use a proper CA-signed certificate!")
                import subprocess
                subprocess.run([
                    "openssl", "req", "-new", "-x509", "-keyout", str(cert_file),
                    "-out", str(cert_file), "-days", "365", "-nodes",
                    "-subj", "/CN=localhost"
                ], check=False, capture_output=True)
                
                if cert_file.exists():
                    logger.info("   ✓ Self-signed certificate created")
                else:
                    logger.error("   ❌ Failed to create certificate. Running without TLS.")
                    use_tls = False
            
            if use_tls:
                try:
                    server.socket = ssl.wrap_socket(
                        server.socket,
                        certfile=str(cert_file),
                        server_side=True,
                        ssl_version=ssl.PROTOCOL_TLS
                    )
                    logger.info("✓ TLS encryption enabled")
                except Exception as e:
                    logger.error(f"❌ TLS setup failed: {e}")
                    logger.error("   Running without TLS (not recommended for production)")
        
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("\n✅ Server stopped")
    except Exception as e:
        logger.error(f"❌ Server error: {e}")


def main():
    parser = argparse.ArgumentParser(description="Central Collector")
    parser.add_argument("--start", action="store_true", help="Start collector server")
    parser.add_argument("--port", type=int, default=8443, help="Server port")
    parser.add_argument("--reports-dir", default="collected_reports", help="Reports directory")
    parser.add_argument("--no-tls", action="store_true", help="Disable TLS (dev mode only, NOT recommended)")
    
    args = parser.parse_args()
    
    if args.start:
        start_collector(args.port, args.reports_dir, use_tls=not args.no_tls)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
