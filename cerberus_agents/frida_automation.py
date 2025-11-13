#!/usr/bin/env python3
"""
Frida Automation Framework - Production Ready
Automated mobile app security testing with Frida
"""

import argparse
import logging
import subprocess
import json
import os
import sys
import time

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class FridaAutomation:
    """Production-ready Frida automation framework"""
    
    def __init__(self, target_app=None, device='usb'):
        self.target_app = target_app
        self.device = device
        self.scripts_dir = 'frida_scripts'
        os.makedirs(self.scripts_dir, exist_ok=True)
        
    def generate_ssl_bypass_script(self):
        """Generate comprehensive SSL pinning bypass script"""
        script = """
// Universal SSL Pinning Bypass for iOS & Android
// Works with most common SSL pinning implementations

console.log("[*] SSL Pinning Bypass Script Loaded");

// iOS SSL Pinning Bypass
if (ObjC.available) {
    console.log("[*] iOS Detected - Hooking SSL/TLS");
    
    // NSURLSession pinning bypass
    var NSURLSession = ObjC.classes.NSURLSession;
    var URLSession_didReceiveChallenge = NSURLSession['- URLSession:didReceiveChallenge:completionHandler:'];
    
    if (URLSession_didReceiveChallenge) {
        Interceptor.attach(URLSession_didReceiveChallenge.implementation, {
            onEnter: function(args) {
                console.log("[+] NSURLSession challenge bypassed");
                var completionHandler = new ObjC.Block(args[3]);
                var impl = completionHandler.implementation;
                completionHandler.implementation = function(disposition, credential) {
                    console.log("[+] Accepting all certificates");
                    impl(1, credential); // NSURLSessionAuthChallengeUseCredential
                };
            }
        });
    }
    
    // AFNetworking bypass
    try {
        var AFHTTPSessionManager = ObjC.classes.AFHTTPSessionManager;
        if (AFHTTPSessionManager) {
            Interceptor.attach(AFHTTPSessionManager['- setSecurityPolicy:'].implementation, {
                onEnter: function(args) {
                    console.log("[+] AFNetworking SSL pinning disabled");
                    var securityPolicy = ObjC.classes.AFSecurityPolicy.policyWithPinningMode_(0);
                    securityPolicy.setAllowInvalidCertificates_(true);
                    securityPolicy.setValidatesDomainName_(false);
                    args[2] = securityPolicy;
                }
            });
        }
    } catch(err) {
        console.log("[-] AFNetworking not found");
    }
    
    // TrustKit bypass
    try {
        var TrustKit = ObjC.classes.TrustKit;
        if (TrustKit) {
            Interceptor.attach(TrustKit['+ initSharedInstanceWithConfiguration:'].implementation, {
                onEnter: function(args) {
                    console.log("[+] TrustKit SSL pinning disabled");
                    args[2] = NULL;
                }
            });
        }
    } catch(err) {
        console.log("[-] TrustKit not found");
    }
}

// Android SSL Pinning Bypass
if (Java.available) {
    console.log("[*] Android Detected - Hooking SSL/TLS");
    
    Java.perform(function() {
        // OkHttp3 CertificatePinner bypass
        try {
            var CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
                console.log('[+] OkHttp3 pinning bypassed for: ' + arguments[0]);
                return;
            };
        } catch(err) {
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
                console.log('[+] SSLContext.init called, replacing TrustManager');
                SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
            };
        } catch(err) {
            console.log("[-] TrustManager bypass failed: " + err);
        }
        
        // Apache HttpClient bypass
        try {
            var DefaultHostnameVerifier = Java.use('org.apache.http.conn.ssl.DefaultHostnameVerifier');
            DefaultHostnameVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function() {
                console.log('[+] Apache HttpClient hostname verification bypassed');
                return true;
            };
        } catch(err) {
            console.log("[-] Apache HttpClient not found");
        }
    });
}

console.log("[*] SSL Pinning Bypass Script Complete");
"""
        
        script_path = f'{self.scripts_dir}/ssl_bypass.js'
        with open(script_path, 'w') as f:
            f.write(script)
        
        logger.info(f"SSL bypass script generated: {script_path}")
        return script_path
    
    def generate_crypto_monitor_script(self):
        """Generate cryptographic operations monitoring script"""
        script = """
// Cryptographic Operations Monitor
// Monitors encryption/decryption, hashing, key generation

console.log("[*] Crypto Monitor Script Loaded");

if (Java.available) {
    Java.perform(function() {
        // Monitor AES encryption
        var Cipher = Java.use('javax.crypto.Cipher');
        
        Cipher.doFinal.overload('[B').implementation = function(data) {
            console.log("[CRYPTO] Cipher.doFinal called");
            console.log("[*] Algorithm: " + this.getAlgorithm());
            console.log("[*] Provider: " + this.getProvider());
            console.log("[*] Input size: " + data.length);
            
            var result = this.doFinal(data);
            console.log("[*] Output size: " + result.length);
            
            return result;
        };
        
        // Monitor MessageDigest (hashing)
        var MessageDigest = Java.use('java.security.MessageDigest');
        MessageDigest.digest.overload('[B').implementation = function(data) {
            console.log("[CRYPTO] MessageDigest.digest called");
            console.log("[*] Algorithm: " + this.getAlgorithm());
            console.log("[*] Input size: " + data.length);
            
            var result = this.digest(data);
            console.log("[*] Hash: " + bytesToHex(result));
            
            return result;
        };
        
        // Monitor SecretKeySpec (key usage)
        var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algorithm) {
            console.log("[CRYPTO] SecretKeySpec created");
            console.log("[*] Algorithm: " + algorithm);
            console.log("[*] Key size: " + key.length + " bytes");
            console.log("[*] Key (hex): " + bytesToHex(key));
            
            return this.$init(key, algorithm);
        };
        
        // Utility function
        function bytesToHex(bytes) {
            var hex = '';
            for (var i = 0; i < bytes.length && i < 32; i++) {
                hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
            }
            return hex + (bytes.length > 32 ? '...' : '');
        }
    });
}

if (ObjC.available) {
    // Monitor CommonCrypto on iOS
    var CCCrypt = Module.findExportByName('libcommonCrypto.dylib', 'CCCrypt');
    if (CCCrypt) {
        Interceptor.attach(CCCrypt, {
            onEnter: function(args) {
                console.log("[CRYPTO] CCCrypt called");
                console.log("[*] Operation: " + args[0]);
                console.log("[*] Algorithm: " + args[1]);
            }
        });
    }
}

console.log("[*] Crypto Monitor Active");
"""
        
        script_path = f'{self.scripts_dir}/crypto_monitor.js'
        with open(script_path, 'w') as f:
            f.write(script)
        
        logger.info(f"Crypto monitor script generated: {script_path}")
        return script_path
    
    def generate_api_intercept_script(self):
        """Generate API request/response interceptor"""
        script = """
// API Request/Response Interceptor
// Logs all HTTP(S) requests and responses

console.log("[*] API Interceptor Script Loaded");

if (Java.available) {
    Java.perform(function() {
        // OkHttp3 interceptor
        try {
            var OkHttpClient = Java.use('okhttp3.OkHttpClient');
            var Request = Java.use('okhttp3.Request');
            var Response = Java.use('okhttp3.Response');
            
            // Intercept OkHttp requests
            var Call = Java.use('okhttp3.Call');
            Call.execute.implementation = function() {
                var request = this.request();
                console.log("[API] HTTP Request:");
                console.log("  URL: " + request.url());
                console.log("  Method: " + request.method());
                
                var headers = request.headers();
                for (var i = 0; i < headers.size(); i++) {
                    console.log("  Header: " + headers.name(i) + ": " + headers.value(i));
                }
                
                var response = this.execute();
                console.log("[API] HTTP Response:");
                console.log("  Code: " + response.code());
                console.log("  Message: " + response.message());
                
                return response;
            };
        } catch(err) {
            console.log("[-] OkHttp3 intercept failed: " + err);
        }
        
        // HttpURLConnection interceptor
        try {
            var HttpURLConnection = Java.use('java.net.HttpURLConnection');
            HttpURLConnection.getInputStream.implementation = function() {
                console.log("[API] HttpURLConnection Request:");
                console.log("  URL: " + this.getURL());
                console.log("  Method: " + this.getRequestMethod());
                console.log("  Response Code: " + this.getResponseCode());
                
                return this.getInputStream();
            };
        } catch(err) {
            console.log("[-] HttpURLConnection intercept failed");
        }
    });
}

if (ObjC.available) {
    // NSURLSession interceptor for iOS
    var NSURLSession = ObjC.classes.NSURLSession;
    var NSURLSession_dataTaskWithRequest = NSURLSession['- dataTaskWithRequest:completionHandler:'];
    
    if (NSURLSession_dataTaskWithRequest) {
        Interceptor.attach(NSURLSession_dataTaskWithRequest.implementation, {
            onEnter: function(args) {
                var request = new ObjC.Object(args[2]);
                console.log("[API] iOS Request:");
                console.log("  URL: " + request.URL().absoluteString());
                console.log("  Method: " + request.HTTPMethod());
                
                var headers = request.allHTTPHeaderFields();
                if (headers) {
                    var enumerator = headers.keyEnumerator();
                    var key;
                    while ((key = enumerator.nextObject()) !== null) {
                        console.log("  Header: " + key + ": " + headers.objectForKey_(key));
                    }
                }
            }
        });
    }
}

console.log("[*] API Interceptor Active");
"""
        
        script_path = f'{self.scripts_dir}/api_intercept.js'
        with open(script_path, 'w') as f:
            f.write(script)
        
        logger.info(f"API interceptor script generated: {script_path}")
        return script_path
    
    def generate_method_tracer_script(self, class_name):
        """Generate method tracer for specific class"""
        script = f"""
// Method Tracer for {class_name}
// Traces all method calls in specified class

console.log("[*] Method Tracer for {class_name}");

if (Java.available) {{
    Java.perform(function() {{
        try {{
            var targetClass = Java.use('{class_name}');
            var methods = targetClass.class.getDeclaredMethods();
            
            methods.forEach(function(method) {{
                var methodName = method.getName();
                var methodOverloads = targetClass[methodName];
                
                if (methodOverloads) {{
                    methodOverloads.overloads.forEach(function(overload) {{
                        overload.implementation = function() {{
                            console.log("[TRACE] {class_name}." + methodName + " called");
                            console.log("  Arguments: " + JSON.stringify(arguments));
                            
                            var result = this[methodName].apply(this, arguments);
                            
                            console.log("  Return: " + result);
                            return result;
                        }};
                    }});
                }}
            }});
            
            console.log("[*] Tracing {len(class_name)} methods in {class_name}");
        }} catch(err) {{
            console.log("[-] Failed to trace {class_name}: " + err);
        }}
    }});
}}

if (ObjC.available) {{
    var targetClass = ObjC.classes.{class_name};
    if (targetClass) {{
        var methods = targetClass.$methods;
        methods.forEach(function(method) {{
            try {{
                var impl = targetClass[method].implementation;
                Interceptor.attach(impl, {{
                    onEnter: function(args) {{
                        console.log("[TRACE] {class_name}." + method + " called");
                    }},
                    onLeave: function(retval) {{
                        console.log("[TRACE] {class_name}." + method + " returned: " + retval);
                    }}
                }});
            }} catch(err) {{}}
        }});
    }}
}}
"""
        
        script_path = f'{self.scripts_dir}/trace_{class_name.replace(".", "_")}.js'
        with open(script_path, 'w') as f:
            f.write(script)
        
        logger.info(f"Method tracer script generated: {script_path}")
        return script_path
    
    def run_frida_script(self, script_path):
        """Execute Frida script on target app"""
        if not self.target_app:
            logger.error("Target app not specified")
            return False
        
        cmd = f"frida -{'U' if self.device == 'usb' else 'D ' + self.device} -f {self.target_app} -l {script_path}"
        
        logger.info(f"Running Frida script: {script_path}")
        logger.info(f"Command: {cmd}")
        logger.info("Press Ctrl+C to stop")
        
        try:
            subprocess.run(cmd, shell=True)
            return True
        except KeyboardInterrupt:
            logger.info("Frida script stopped")
            return True
        except Exception as e:
            logger.error(f"Failed to run script: {e}")
            return False
    
    def generate_all_scripts(self):
        """Generate all common Frida scripts"""
        logger.info("Generating all Frida scripts...")
        
        scripts = []
        scripts.append(self.generate_ssl_bypass_script())
        scripts.append(self.generate_crypto_monitor_script())
        scripts.append(self.generate_api_intercept_script())
        
        logger.info(f"Generated {len(scripts)} scripts")
        
        return scripts


def main():
    parser = argparse.ArgumentParser(description='Frida Automation Framework')
    parser.add_argument('--app', help='Target app bundle ID or package name')
    parser.add_argument('--device', default='usb', help='Device ID (default: usb)')
    parser.add_argument('--generate-ssl', action='store_true', help='Generate SSL bypass script')
    parser.add_argument('--generate-crypto', action='store_true', help='Generate crypto monitor script')
    parser.add_argument('--generate-api', action='store_true', help='Generate API interceptor script')
    parser.add_argument('--trace-class', help='Generate method tracer for class')
    parser.add_argument('--run-script', help='Run Frida script')
    parser.add_argument('--generate-all', action='store_true', help='Generate all scripts')
    
        parser.add_argument('--authorized', action='store_true',
                       help='Confirm you have authorization to perform this action')
    args = parser.parse_args()
    
    frida = FridaAutomation(target_app=args.app, device=args.device)
    
    print("=" * 70)
    print("FRIDA AUTOMATION FRAMEWORK")
    print("=" * 70)
    print("\nAutomated Security Testing:")
    print("• SSL/TLS Pinning Bypass (Universal)")
    print("• Cryptographic Operations Monitoring")
    print("• API Request/Response Interception")
    print("• Method Tracing & Hooking")
    print("• Runtime Analysis Automation")
    print("\nSupported Platforms:")
    print("• iOS (with Objection integration)")
    print("• Android")
    print("=" * 70)
    
    if args.generate_ssl:
        script = frida.generate_ssl_bypass_script()
        print(f"\nSSL bypass script: {script}")
    
    if args.generate_crypto:
        script = frida.generate_crypto_monitor_script()
        print(f"\nCrypto monitor script: {script}")
    
    if args.generate_api:
        script = frida.generate_api_intercept_script()
        print(f"\nAPI interceptor script: {script}")
    
    if args.trace_class:
        script = frida.generate_method_tracer_script(args.trace_class)
        print(f"\nMethod tracer script: {script}")
    
    if args.run_script:
        frida.run_frida_script(args.run_script)
    
    if args.generate_all:
        scripts = frida.generate_all_scripts()
        print(f"\nGenerated {len(scripts)} scripts:")
        for s in scripts:
            print(f"  - {s}")
    
    if len(sys.argv) == 1:
        parser.print_help()


if __name__ == '__main__':
    main()
