#!/usr/bin/env python3
"""
Advanced tests for Cerberus Agents new modules

Run with: python tests/test_advanced.py
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestNewModules(unittest.TestCase):
    """Test new advanced modules"""
    
    def test_import_web_vuln_scanner(self):
        """Test web_vuln_scanner import"""
        from cerberus_agents import web_vuln_scanner
        self.assertTrue(hasattr(web_vuln_scanner, 'WebVulnScanner'))
    
    def test_import_hash_cracker(self):
        """Test hash_cracker import"""
        from cerberus_agents import hash_cracker
        self.assertTrue(hasattr(hash_cracker, 'HashCracker'))
    
    def test_import_payload_generator(self):
        """Test payload_generator import"""
        from cerberus_agents import payload_generator
        self.assertTrue(hasattr(payload_generator, 'PayloadGenerator'))
    
    def test_import_report_aggregator(self):
        """Test report_aggregator import"""
        from cerberus_agents import report_aggregator
        self.assertTrue(hasattr(report_aggregator, 'ReportAggregator'))


class TestHashCracker(unittest.TestCase):
    """Test hash cracker functionality"""
    
    def test_md5_hashing(self):
        """Test MD5 hash generation"""
        from cerberus_agents.hash_cracker import HashCracker
        
        cracker = HashCracker("5f4dcc3b5aa765d61d8327deb882cf99", "md5")
        result = cracker.hash_string("password")
        
        self.assertEqual(result, "5f4dcc3b5aa765d61d8327deb882cf99")
    
    def test_sha256_hashing(self):
        """Test SHA256 hash generation"""
        from cerberus_agents.hash_cracker import HashCracker
        
        cracker = HashCracker("test", "sha256")
        result = cracker.hash_string("password")
        
        self.assertEqual(len(result), 64)


class TestPayloadGenerator(unittest.TestCase):
    """Test payload generator functionality"""
    
    def test_reverse_shell_generation(self):
        """Test reverse shell payload generation"""
        from cerberus_agents.payload_generator import PayloadGenerator
        
        gen = PayloadGenerator()
        payloads = gen.generate_reverse_shell("10.0.0.1", 4444, "bash")
        
        self.assertIn("bash", payloads)
        self.assertIn("10.0.0.1", payloads["bash"])
        self.assertIn("4444", payloads["bash"])
    
    def test_web_shell_generation(self):
        """Test web shell payload generation"""
        from cerberus_agents.payload_generator import PayloadGenerator
        
        gen = PayloadGenerator()
        payloads = gen.generate_web_shell("php")
        
        self.assertIn("php_simple", payloads)
        self.assertIn("<?php", payloads["php_simple"])
    
    def test_sqli_payloads(self):
        """Test SQL injection payload generation"""
        from cerberus_agents.payload_generator import PayloadGenerator
        
        gen = PayloadGenerator()
        payloads = gen.generate_sqli_payloads()
        
        self.assertIn("basic_auth_bypass", payloads)
        self.assertIn("union_based", payloads)
        self.assertTrue(len(payloads["basic_auth_bypass"]) > 0)


class TestWebVulnScanner(unittest.TestCase):
    """Test web vulnerability scanner"""
    
    def test_scanner_initialization(self):
        """Test scanner initialization"""
        from cerberus_agents.web_vuln_scanner import WebVulnScanner
        
        scanner = WebVulnScanner("https://example.com")
        self.assertEqual(scanner.target, "https://example.com")
        self.assertTrue(len(scanner.sqli_payloads) > 0)
        self.assertTrue(len(scanner.xss_payloads) > 0)


if __name__ == "__main__":
    unittest.main()
