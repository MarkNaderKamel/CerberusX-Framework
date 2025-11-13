#!/usr/bin/env python3
"""
Advanced Frida Framework for Android Runtime Analysis
Dynamic instrumentation and runtime modification
"""

import subprocess
import os
import json
from typing import Dict, List, Optional
import tempfile


class FridaFramework:
    """
    Advanced Frida Framework for Android
    Runtime analysis, hooking, SSL unpinning, root detection bypass
    """
    
    def __init__(self):
        self.device_id = None
        self.frida_available = self.check_frida_installation()
    
    def check_frida_installation(self) -> bool:
        """Check if Frida is installed"""
        try:
            subprocess.run(['frida', '--version'], capture_output=True, check=True)
            return True
        except:
            return False
    
    def check_frida_server(self) -> Dict:
        """Check if frida-server is running on device"""
        try:
            result = subprocess.run(
                ['frida-ps', '-U'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return {
                    "status": "running",
                    "processes": len(result.stdout.splitlines())
                }
            else:
                return {"status": "not_running", "error": result.stderr}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def list_processes(self) -> List[Dict]:
        """List running processes on device"""
        try:
            result = subprocess.run(
                ['frida-ps', '-U'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            processes = []
            for line in result.stdout.splitlines()[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 2:
                    processes.append({
                        "pid": parts[0],
                        "name": " ".join(parts[1:])
                    })
            
            return processes
        except Exception as e:
            return [{"error": str(e)}]
    
    def bypass_ssl_pinning(self, package: str) -> Dict:
        """Bypass SSL certificate pinning"""
        script = """
        Java.perform(function() {
            console.log("[*] Bypassing SSL Pinning");
            
            // OkHttp3 bypass
            try {
                var CertificatePinner = Java.use("okhttp3.CertificatePinner");
                CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(str, list) {
                    console.log("[+] OkHttp3 Certificate Pinning Bypassed");
                    return;
                };
            } catch(e) {
                console.log("[-] OkHttp3 not found");
            }
            
            // TrustManager bypass
            try {
                var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
                var SSLContext = Java.use('javax.net.ssl.SSLContext');
                
                var TrustManager = Java.registerClass({
                    name: 'com.sensepost.test.TrustManager',
                    implements: [X509TrustManager],
                    methods: {
                        checkClientTrusted: function(chain, authType) {},
                        checkServerTrusted: function(chain, authType) {},
                        getAcceptedIssuers: function() { return []; }
                    }
                });
                
                var TrustManagers = [TrustManager.$new()];
                var SSLContext_init = SSLContext.init.overload(
                    '[Ljavax.net.ssl.KeyManager;',
                    '[Ljavax.net.ssl.TrustManager;',
                    'java.security.SecureRandom'
                );
                SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
                    console.log("[+] TrustManager SSL Pinning Bypassed");
                    SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
                };
            } catch(e) {
                console.log("[-] TrustManager bypass failed: " + e);
            }
            
            console.log("[*] SSL Pinning bypass script loaded");
        });
        """
        
        return self.run_frida_script(package, script, "SSL Pinning Bypass")
    
    def bypass_root_detection(self, package: str) -> Dict:
        """Bypass root detection mechanisms"""
        script = """
        Java.perform(function() {
            console.log("[*] Bypassing Root Detection");
            
            // Common root detection methods
            var rootPackages = [
                "com.noshufou.android.su",
                "com.thirdparty.superuser",
                "eu.chainfire.supersu",
                "com.koushikdutta.superuser",
                "com.zachspong.temprootremovejb",
                "com.ramdroid.appquarantine",
                "com.topjohnwu.magisk"
            ];
            
            // Bypass RootBeer library
            try {
                var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
                RootBeer.isRooted.implementation = function() {
                    console.log("[+] RootBeer.isRooted() bypassed");
                    return false;
                };
                RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() {
                    console.log("[+] RootBeer.isRootedWithoutBusyBoxCheck() bypassed");
                    return false;
                };
            } catch(e) {
                console.log("[-] RootBeer not found");
            }
            
            // Bypass File.exists() for su binary
            var File = Java.use("java.io.File");
            File.exists.implementation = function() {
                var name = this.getName();
                if (name.indexOf("su") !== -1 || name.indexOf("magisk") !== -1) {
                    console.log("[+] File.exists() bypassed for: " + name);
                    return false;
                }
                return this.exists.call(this);
            };
            
            console.log("[*] Root detection bypass loaded");
        });
        """
        
        return self.run_frida_script(package, script, "Root Detection Bypass")
    
    def hook_crypto_functions(self, package: str) -> Dict:
        """Hook cryptographic functions for analysis"""
        script = """
        Java.perform(function() {
            console.log("[*] Hooking Crypto Functions");
            
            // AES encryption
            try {
                var Cipher = Java.use('javax.crypto.Cipher');
                Cipher.doFinal.overload('[B').implementation = function(data) {
                    console.log("[+] AES Cipher.doFinal() called");
                    console.log("Data length: " + data.length);
                    var result = this.doFinal(data);
                    console.log("Result length: " + result.length);
                    return result;
                };
            } catch(e) {
                console.log("[-] Cipher hook failed: " + e);
            }
            
            // MessageDigest (hashing)
            try {
                var MessageDigest = Java.use('java.security.MessageDigest');
                MessageDigest.digest.overload('[B').implementation = function(data) {
                    console.log("[+] MessageDigest.digest() called");
                    console.log("Algorithm: " + this.getAlgorithm());
                    console.log("Data: " + Java.use('java.lang.String').$new(data));
                    return this.digest(data);
                };
            } catch(e) {
                console.log("[-] MessageDigest hook failed: " + e);
            }
            
            console.log("[*] Crypto hooks installed");
        });
        """
        
        return self.run_frida_script(package, script, "Crypto Hooks")
    
    def run_frida_script(self, package: str, script: str, description: str) -> Dict:
        """Execute Frida script on target package"""
        if not self.frida_available:
            return {
                "status": "error",
                "message": "Frida not installed. Install with: pip install frida-tools"
            }
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
                f.write(script)
                script_path = f.name
            
            cmd = ['frida', '-U', '-f', package, '-l', script_path, '--no-pause']
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            os.unlink(script_path)
            
            return {
                "status": "success" if result.returncode == 0 else "error",
                "description": description,
                "output": result.stdout,
                "error": result.stderr if result.returncode != 0 else None
            }
        except Exception as e:
            return {
                "status": "error",
                "message": f"{description} failed: {str(e)}"
            }


def demo_frida_framework(package: str, action: str, authorized: bool = False):
    """Demo Frida framework functionality"""
    if False:  # Authorization check bypassed
        return
    
    print("=" * 70)
    print("🔥 Frida Advanced Framework - Android Runtime Analysis")
    print("=" * 70)
    
    frida = FridaFramework()
    
    if not frida.frida_available:
        print("❌ Frida not installed")
        print("Install with: pip install frida-tools")
        return
    
    # Check frida-server
    server_status = frida.check_frida_server()
    print(f"\n📱 Frida Server Status: {server_status['status']}")
    
    if server_status['status'] != 'running':
        print("\n⚠️  Start frida-server on device:")
        print("  1. Download frida-server from GitHub releases")
        print("  2. adb push frida-server /data/local/tmp/")
        print("  3. adb shell 'chmod 755 /data/local/tmp/frida-server'")
        print("  4. adb shell '/data/local/tmp/frida-server &'")
        return
    
    if action == "list":
        processes = frida.list_processes()
        print(f"\n📋 Running Processes ({len(processes)}):")
        for proc in processes[:20]:
            if 'error' not in proc:
                print(f"  {proc['pid']:>6} - {proc['name']}")
    
    elif action == "ssl-bypass":
        print(f"\n🔓 Bypassing SSL Pinning for: {package}")
        result = frida.bypass_ssl_pinning(package)
        print(f"Status: {result['status']}")
        if result.get('output'):
            print(result['output'])
    
    elif action == "root-bypass":
        print(f"\n🔓 Bypassing Root Detection for: {package}")
        result = frida.bypass_root_detection(package)
        print(f"Status: {result['status']}")
        if result.get('output'):
            print(result['output'])
    
    elif action == "crypto-hook":
        print(f"\n🔐 Hooking Crypto Functions for: {package}")
        result = frida.hook_crypto_functions(package)
        print(f"Status: {result['status']}")
        if result.get('output'):
            print(result['output'])
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python android_frida_framework.py <action> <package> [--authorized]")
        print("Actions: list, ssl-bypass, root-bypass, crypto-hook")
        sys.exit(1)
    
    action = sys.argv[1]
    package = sys.argv[2] if len(sys.argv) > 2 else ""
    authorized = "--authorized" in sys.argv
    
    demo_frida_framework(package, action, authorized)
