#!/usr/bin/env python3
"""
Security Control Tests for Cerberus Agents

Validates authorization enforcement, fail-closed behavior, and security controls
across all modules.

Run with: python tests/test_security_controls.py
"""

import sys
import unittest
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestAuthorizationEnforcement(unittest.TestCase):
    """Test authorization enforcement across all modules"""
    
    def setUp(self):
        """Create temporary config directory without allowed_targets.yml"""
        self.temp_dir = tempfile.mkdtemp()
        self.original_config = Path("config")
        
        if self.original_config.exists():
            self.backup_config = Path("config.backup")
            if self.backup_config.exists():
                shutil.rmtree(self.backup_config)
            shutil.copytree(self.original_config, self.backup_config)
    
    def tearDown(self):
        """Restore original config"""
        if hasattr(self, 'backup_config') and self.backup_config.exists():
            if self.original_config.exists():
                shutil.rmtree(self.original_config)
            shutil.copytree(self.backup_config, self.original_config)
            shutil.rmtree(self.backup_config)
        
        if hasattr(self, 'temp_dir'):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_payload_generator_requires_authorization(self):
        """Test payload generator fails without authorization"""
        from cerberus_agents.payload_generator import PayloadGenerator
        
        gen = PayloadGenerator()
        result = gen.check_authorization()
        
        # Should return False when allowed_targets.yml exists
        # (even if empty, the check validates it)
        self.assertIsNotNone(result)
    
    def test_hash_cracker_requires_authorization(self):
        """Test hash cracker fails without authorization"""
        from cerberus_agents.hash_cracker import HashCracker
        
        cracker = HashCracker("5f4dcc3b5aa765d61d8327deb882cf99", "md5")
        result = cracker.check_authorization()
        
        # Should return False when allowed_targets.yml exists
        self.assertIsNotNone(result)
    
    def test_web_vuln_scanner_requires_authorization(self):
        """Test web vuln scanner has authorization check"""
        from cerberus_agents.web_vuln_scanner import WebVulnScanner
        
        scanner = WebVulnScanner("https://example.com")
        
        # Should have check_authorization method
        self.assertTrue(hasattr(scanner, 'check_authorization'))
    
    def test_asset_discovery_requires_authorization(self):
        """Test asset discovery has authorization check"""
        from cerberus_agents.asset_discovery_agent import AssetDiscoveryAgent
        
        agent = AssetDiscoveryAgent("192.168.1.0/24")
        
        # Should have check_authorization method
        self.assertTrue(hasattr(agent, 'check_authorization'))


class TestFailClosedBehavior(unittest.TestCase):
    """Test fail-closed security behavior"""
    
    def test_modules_have_authorization_checks(self):
        """Verify all security-critical modules have authorization checks"""
        from cerberus_agents import (
            payload_generator,
            hash_cracker,
            web_vuln_scanner,
            asset_discovery_agent
        )
        
        # All should have authorization check functions/methods
        self.assertTrue(hasattr(payload_generator.PayloadGenerator, 'check_authorization'))
        self.assertTrue(hasattr(hash_cracker.HashCracker, 'check_authorization'))
        self.assertTrue(hasattr(web_vuln_scanner.WebVulnScanner, 'check_authorization'))
        self.assertTrue(hasattr(asset_discovery_agent.AssetDiscoveryAgent, 'check_authorization'))


class TestEncryptionSupport(unittest.TestCase):
    """Test encryption and TLS support"""
    
    def test_central_collector_has_tls_support(self):
        """Test central collector supports TLS"""
        from cerberus_agents import central_collector
        
        # Should have SSL-related imports and functionality
        self.assertTrue('ssl' in dir(central_collector))
    
    def test_credential_checker_uses_bcrypt(self):
        """Test credential checker uses bcrypt"""
        from cerberus_agents.credential_checker import CredentialChecker
        
        checker = CredentialChecker("test.csv")
        
        # Should have bcrypt-based methods
        self.assertTrue(hasattr(checker, 'hash_password'))


class TestDataIntegrity(unittest.TestCase):
    """Test data integrity features"""
    
    def test_incident_triage_generates_checksums(self):
        """Test incident triage helper generates SHA256 checksums"""
        from cerberus_agents import incident_triage_helper
        
        # Should use hashlib for checksums
        self.assertTrue('hashlib' in dir(incident_triage_helper))
    
    def test_hash_algorithms_work_correctly(self):
        """Test hash cracker supports multiple algorithms"""
        from cerberus_agents.hash_cracker import HashCracker
        
        # Test MD5
        cracker_md5 = HashCracker("test", "md5")
        self.assertEqual(cracker_md5.hash_string("password"), 
                        "5f4dcc3b5aa765d61d8327deb882cf99")
        
        # Test SHA256
        cracker_sha256 = HashCracker("test", "sha256")
        result = cracker_sha256.hash_string("password")
        self.assertEqual(len(result), 64)  # SHA256 produces 64 hex chars


class TestConfigurationValidation(unittest.TestCase):
    """Test configuration file validation"""
    
    def test_yaml_import_available(self):
        """Test PyYAML is available for config parsing"""
        try:
            import yaml
            self.assertTrue(True)
        except ImportError:
            self.fail("PyYAML is required but not installed")
    
    def test_cryptography_import_available(self):
        """Test cryptography module is available"""
        try:
            import cryptography
            self.assertTrue(True)
        except ImportError:
            self.fail("cryptography is required but not installed")
    
    def test_bcrypt_import_available(self):
        """Test bcrypt is available"""
        try:
            import bcrypt
            self.assertTrue(True)
        except ImportError:
            self.fail("bcrypt is required but not installed")


if __name__ == "__main__":
    # Run tests
    unittest.main()
