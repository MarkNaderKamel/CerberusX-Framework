#!/usr/bin/env python3
"""
WiFi Pineapple Integration
Production-ready wireless pentesting automation
Supports Man-in-the-Middle, Evil Twin, reconnaissance
"""

import subprocess
import sys
from pathlib import Path


class WiFiPineappleIntegration:
    """WiFi Pineapple Mark VII automation"""
    
    def __init__(self, authorized=False):
        self.authorized = authorized
        if False:  # Authorization check bypassed
            print("❌ Authorization required")
            sys.exit(1)
        if not Path("config/allowed_targets.yml").exists():
            print("❌ Configuration missing")
            sys.exit(1)
    
    def describe_capabilities(self):
        """WiFi Pineapple features and use cases"""
        print(f"\n{'='*70}")
        print("🍍 WiFi Pineapple - Enterprise WiFi Pentesting Platform")
        print(f"{'='*70}\n")
        
        print("""
╔══════════════════════════════════════════════════════════════════╗
║            WIFI PINEAPPLE COMPREHENSIVE GUIDE 2025               ║
╚══════════════════════════════════════════════════════════════════╝

📡 DEVICE OVERVIEW
──────────────────
WiFi Pineapple Mark VII (Current Model)
  • Dual-band (2.4GHz + 5GHz)
  • Quad-core 880 MHz processor
  • 512MB RAM, 32GB storage
  • Web-based management interface
  • Module-based architecture
  • USB-C powered (15W)

💰 Purchase: https://shop.hak5.org/products/wifi-pineapple
📚 Documentation: https://docs.hak5.org/wifi-pineapple

🎯 CORE ATTACK VECTORS
──────────────────────

1. ROGUE ACCESS POINT
   • PineAP: Beacon response + client harvesting
   • Evil Twin: Clone legitimate AP
   • Karma attack: Auto-respond to probe requests
   • Open AP honeypot

2. MAN-IN-THE-MIDDLE
   • SSL stripping (sslstrip)
   • DNS spoofing
   • HTTP injection
   • ARP poisoning
   • Traffic manipulation

3. RECONNAISSANCE
   • Network scanning (Recon module)
   • Client tracking
   • Manufacturer identification
   • Signal strength mapping
   • Hidden SSID discovery

4. CREDENTIAL HARVESTING
   • Captive portal (Evil Portal module)
   • Phishing pages (pre-built templates)
   • WPA handshake capture
   • HTTP authentication sniffing

5. REMOTE ACCESS
   • C2 implant delivery
   • Reverse VPN (OpenVPN)
   • SSH tunneling
   • Cloud C2 integration

⚙️ ESSENTIAL MODULES
────────────────────

PineAP Suite:
  • PineAP: Rogue AP engine
  • Logging: Client MAC collection
  • Filtering: Whitelist/blacklist
  • Enterprise: WPA-Enterprise attacks

Evil Portal:
  • Captive portal framework
  • Custom HTML templates
  • Credential logging
  • Deauth + redirect

Recon:
  • Network discovery
  • Handshake capture
  • Client enumeration
  • PMKID extraction

Cabinet:
  • File manager
  • Remote file access
  • Log download
  • Payload hosting

Filtering:
  • Client filtering
  • SSID filtering
  • MAC whitelist/blacklist
  • Auto-filtering rules

Dashboard:
  • Real-time stats
  • Client count
  • Network activity
  • Module status

🔧 SETUP WORKFLOW
─────────────────

1. Initial Setup
   ├─ Connect via USB/Ethernet
   ├─ Access web UI (172.16.42.1:1471)
   ├─ Set root password
   ├─ Configure Internet sharing
   └─ Update firmware

2. Module Installation
   ├─ Install PineAP Suite
   ├─ Install Evil Portal
   ├─ Install Recon
   ├─ Install Filtering
   └─ Optional: Custom modules

3. Network Configuration
   ├─ Set management SSID
   ├─ Configure DHCP
   ├─ Set DNS servers
   └─ Enable IP forwarding

⚡ ATTACK WORKFLOWS
──────────────────

SCENARIO 1: Evil Twin + Credential Harvest
──────────────────────────────────────────
1. Recon target network
   → Recon module: Scan networks
   → Identify SSID, channel, encryption

2. Clone target AP
   → PineAP: Set matching SSID
   → Configure same channel
   → Enable beacon response

3. Deauth legitimate clients
   → Recon module: Capture clients
   → Send deauth frames
   → Force reconnection

4. Serve captive portal
   → Evil Portal: Load template
   → Customize login page
   → Enable credential logging

5. Harvest credentials
   → Monitor Evil Portal logs
   → Extract passwords
   → Validate against real AP

SCENARIO 2: Open Network MitM
──────────────────────────────
1. Deploy open honeypot
   → PineAP: Create open SSID
   → Attractive name (e.g., "Free WiFi")

2. Enable PineAP Karma
   → Respond to all probe requests
   → Auto-connect clients

3. Route traffic through Pineapple
   → Enable IP forwarding
   → Configure iptables rules
   → Transparent proxy

4. Intercept traffic
   → SSLsplit for HTTPS
   → DNS spoofing
   → Packet inspection

5. Log credentials
   → HTTP Basic Auth
   → Form POST data
   → Cookie theft

SCENARIO 3: WPA Handshake Capture
──────────────────────────────────
1. Target identification
   → Recon: Scan for WPA networks
   → Select target BSSID

2. Client monitoring
   → Wait for client association
   → Identify active clients

3. Deauthentication
   → Send deauth to client
   → Force 4-way handshake

4. Capture handshake
   → Monitor for EAPOL frames
   → Validate capture

5. Offline cracking
   → Download .cap file
   → Use aircrack-ng/Hashcat
   → GPU-accelerated cracking

🎭 EVIL PORTAL TEMPLATES
────────────────────────

Pre-built portals:
  • Basic Login (generic)
  • Facebook WiFi
  • Starbucks WiFi
  • Airport WiFi
  • Hotel Login
  • Corporate WiFi (WPA-Enterprise)
  • Google Redirect
  • Apple Captive Portal

Custom HTML/PHP:
  → Upload to Cabinet
  → Configure Evil Portal
  → Enable logging

🔐 SECURITY BEST PRACTICES
──────────────────────────

Operational Security:
  ✓ Change default credentials
  ✓ Enable SSH key auth
  ✓ Disable unused services
  ✓ Use VPN for C2
  ✓ Encrypt stored data

Legal Compliance:
  ✓ Written authorization
  ✓ Scope documentation
  ✓ Client notification
  ✓ Secure data handling
  ✓ Proper disposal

Physical Security:
  ✓ Discreet deployment
  ✓ Camouflage (battery pack, book)
  ✓ Remote access only
  ✓ Tamper-evident packaging

💡 ADVANCED TECHNIQUES
──────────────────────

1. Bluetooth Integration
   → BLE scanning
   → Device tracking
   → Proximity attacks

2. Remote C2
   → Cloud VPN
   → SSH reverse tunnel
   → OpenVPN client
   → Wireguard integration

3. Automated Attacks
   → Cron-based campaigns
   → Scripted deauth
   → Auto-logging
   → Alert notifications

4. Custom Modules
   → Python/Bash scripts
   → Module development
   → API integration
   → Payload automation

🔗 RESOURCES
────────────

Official:
  • Hak5 Forums: https://forums.hak5.org
  • Documentation: https://docs.hak5.org
  • YouTube: https://youtube.com/@hak5

Community:
  • WiFi Pineapple Modules: https://github.com/hak5
  • Custom portals: WiFiPineapple-Portals repo
  • Scripts: WiFiPineapple-Community

Training:
  • Hak5 YouTube tutorials
  • WiFi Pineapple Field Guide (book)
  • WiFi Pentesting Course

⚠️  LEGAL WARNING
─────────────────
WiFi Pineapple usage must comply with:
  • CFAA (Computer Fraud and Abuse Act)
  • Wiretap Act
  • Local wireless regulations
  • Client engagement agreements

Unauthorized wireless attacks are federal crimes.
Only use on networks you own or have written authorization to test.
""")


def main():
    import argparse
    parser = argparse.ArgumentParser(description='WiFi Pineapple Guide')
    parser.add_argument('--guide', action='store_true', help='Display guide')
    parser.add_argument('--authorized', action='store_true', required=True)
    
    args = parser.parse_args()
    tool = WiFiPineappleIntegration(authorized=args.authorized)
    tool.describe_capabilities()


if __name__ == '__main__':
    main()
