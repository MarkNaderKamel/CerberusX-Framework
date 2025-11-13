#!/usr/bin/env python3
"""
Fail-Closed Security Tests

Validates that all modules properly fail when authorization is missing or invalid.

Run with: python tests/test_fail_closed.py
"""

import sys
import unittest
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestFailClosedWithoutConfig(unittest.TestCase):
    """Test modules fail when config/allowed_targets.yml is missing"""
    
    def setUp(self):
        """Temporarily move config directory"""
        self.config_dir = Path("config")
        self.backup_dir = Path("config.test_backup")
        
        if self.config_dir.exists():
            if self.backup_dir.exists():
                shutil.rmtree(self.backup_dir)
            shutil.move(self.config_dir, self.backup_dir)
    
    def tearDown(self):
        """Restore config directory"""
        if self.backup_dir.exists():
            if self.config_dir.exists():
                shutil.rmtree(self.config_dir)
            shutil.move(self.backup_dir, self.config_dir)
    
    def test_payload_generator_fails_without_config(self):
        """Payload generator must fail without allowed_targets.yml"""
        from cerberus_agents.payload_generator import PayloadGenerator
        
        gen = PayloadGenerator()
        result = gen.check_authorization()
        
        self.assertFalse(result, "Payload generator should FAIL without config file")
    
    def test_hash_cracker_fails_without_config(self):
        """Hash cracker must fail without allowed_targets.yml"""
        from cerberus_agents.hash_cracker import HashCracker
        
        cracker = HashCracker("abc123", "md5")
        result = cracker.check_authorization()
        
        self.assertFalse(result, "Hash cracker should FAIL without config file")


class TestFailClosedWithEmptyConfig(unittest.TestCase):
    """Test modules fail when allowed_targets.yml is empty or invalid"""
    
    def setUp(self):
        """Create empty config file"""
        self.config_dir = Path("config")
        self.config_file = self.config_dir / "allowed_targets.yml"
        self.backup_file = self.config_dir / "allowed_targets.yml.backup"
        
        if self.config_file.exists():
            shutil.copy(self.config_file, self.backup_file)
        
        self.config_dir.mkdir(exist_ok=True)
        self.config_file.write_text("")  # Empty file
    
    def tearDown(self):
        """Restore original config"""
        if self.backup_file.exists():
            shutil.move(self.backup_file, self.config_file)
    
    def test_payload_generator_fails_with_empty_config(self):
        """Payload generator must fail with empty config"""
        from cerberus_agents.payload_generator import PayloadGenerator
        
        gen = PayloadGenerator()
        result = gen.check_authorization()
        
        self.assertFalse(result, "Payload generator should FAIL with empty config")
    
    def test_hash_cracker_fails_with_empty_config(self):
        """Hash cracker must fail with empty config"""
        from cerberus_agents.hash_cracker import HashCracker
        
        cracker = HashCracker("abc123", "md5")
        result = cracker.check_authorization()
        
        self.assertFalse(result, "Hash cracker should FAIL with empty config")


class TestFailClosedWithInvalidConfig(unittest.TestCase):
    """Test modules fail when allowed_targets.yml has no authorization scope"""
    
    def setUp(self):
        """Create invalid config (no subnets or domains)"""
        self.config_dir = Path("config")
        self.config_file = self.config_dir / "allowed_targets.yml"
        self.backup_file = self.config_dir / "allowed_targets.yml.backup"
        
        if self.config_file.exists():
            shutil.copy(self.config_file, self.backup_file)
        
        self.config_dir.mkdir(exist_ok=True)
        self.config_file.write_text("# No authorization scope defined\n")
    
    def tearDown(self):
        """Restore original config"""
        if self.backup_file.exists():
            shutil.move(self.backup_file, self.config_file)
    
    def test_payload_generator_fails_without_scope(self):
        """Payload generator must fail without authorization scope"""
        from cerberus_agents.payload_generator import PayloadGenerator
        
        gen = PayloadGenerator()
        result = gen.check_authorization()
        
        self.assertFalse(result, "Payload generator should FAIL without authorization scope")
    
    def test_hash_cracker_fails_without_scope(self):
        """Hash cracker must fail without authorization scope"""
        from cerberus_agents.hash_cracker import HashCracker
        
        cracker = HashCracker("abc123", "md5")
        result = cracker.check_authorization()
        
        self.assertFalse(result, "Hash cracker should FAIL without authorization scope")


class TestSuccessWithValidConfig(unittest.TestCase):
    """Test modules succeed with proper authorization"""
    
    def setUp(self):
        """Ensure valid config exists"""
        self.config_dir = Path("config")
        self.config_file = self.config_dir / "allowed_targets.yml"
        
        self.config_dir.mkdir(exist_ok=True)
        if not self.config_file.exists():
            self.config_file.write_text("""
allowed_subnets:
  - "192.168.1.0/24"

allowed_domains:
  - "example.com"
""")
    
    def test_payload_generator_succeeds_with_valid_config(self):
        """Payload generator should succeed with valid config"""
        from cerberus_agents.payload_generator import PayloadGenerator
        
        gen = PayloadGenerator()
        result = gen.check_authorization()
        
        self.assertTrue(result, "Payload generator should SUCCEED with valid config")
    
    def test_hash_cracker_succeeds_with_valid_config(self):
        """Hash cracker should succeed with valid config"""
        from cerberus_agents.hash_cracker import HashCracker
        
        cracker = HashCracker("abc123", "md5")
        result = cracker.check_authorization()
        
        self.assertTrue(result, "Hash cracker should SUCCEED with valid config")


if __name__ == "__main__":
    unittest.main()
