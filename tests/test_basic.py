#!/usr/bin/env python3
"""
Basic tests for Cerberus Agents

Run with: python -m pytest tests/
or: python tests/test_basic.py
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestImports(unittest.TestCase):
    """Test that all modules can be imported"""
    
    def test_import_asset_discovery(self):
        """Test asset_discovery_agent import"""
        from cerberus_agents import asset_discovery_agent
        self.assertTrue(hasattr(asset_discovery_agent, 'AssetDiscoveryAgent'))
    
    def test_import_recon_reporter(self):
        """Test automated_recon_reporter import"""
        from cerberus_agents import automated_recon_reporter
        self.assertTrue(hasattr(automated_recon_reporter, 'AutomatedReconReporter'))
    
    def test_import_credential_checker(self):
        """Test credential_checker import"""
        from cerberus_agents import credential_checker
        self.assertTrue(hasattr(credential_checker, 'CredentialChecker'))
    
    def test_import_canary(self):
        """Test tiny_canary_agent import"""
        from cerberus_agents import tiny_canary_agent
        self.assertTrue(hasattr(tiny_canary_agent, 'TinyCanaryAgent'))
    
    def test_import_task_runner(self):
        """Test pentest_task_runner import"""
        from cerberus_agents import pentest_task_runner
        self.assertTrue(hasattr(pentest_task_runner, 'PentestTaskRunner'))
    
    def test_import_incident_triage(self):
        """Test incident_triage_helper import"""
        from cerberus_agents import incident_triage_helper
        self.assertTrue(hasattr(incident_triage_helper, 'IncidentTriageHelper'))
    
    def test_import_collector(self):
        """Test central_collector import"""
        from cerberus_agents import central_collector
        self.assertTrue(hasattr(central_collector, 'CentralCollector'))


class TestConfigFiles(unittest.TestCase):
    """Test that configuration files exist"""
    
    def test_allowed_targets_exists(self):
        """Test allowed_targets.yml exists"""
        self.assertTrue(Path("config/allowed_targets.yml").exists())
    
    def test_common_passwords_exists(self):
        """Test common_passwords.txt exists"""
        self.assertTrue(Path("config/common_passwords.txt").exists())
    
    def test_canary_config_exists(self):
        """Test canary_config.json exists"""
        self.assertTrue(Path("config/canary_config.json").exists())
    
    def test_pentest_tasks_exists(self):
        """Test pentest_tasks.json exists"""
        self.assertTrue(Path("config/pentest_tasks.json").exists())


class TestCredentialChecker(unittest.TestCase):
    """Test credential checker functionality"""
    
    def test_password_strength_weak(self):
        """Test weak password detection"""
        from cerberus_agents.credential_checker import CredentialChecker
        
        checker = CredentialChecker("samples/users.csv.example")
        result = checker.check_password_strength("123456")
        
        self.assertEqual(result["strength"], "Very Weak")
        self.assertLess(result["score"], 40)
    
    def test_password_strength_strong(self):
        """Test strong password detection"""
        from cerberus_agents.credential_checker import CredentialChecker
        
        checker = CredentialChecker("samples/users.csv.example")
        result = checker.check_password_strength("MyStr0ng!P@ssw0rd2024")
        
        self.assertIn(result["strength"], ["Strong", "Moderate"])
        self.assertGreater(result["score"], 50)


class TestCanaryAgent(unittest.TestCase):
    """Test canary agent functionality"""
    
    def test_config_loading(self):
        """Test canary config loading"""
        from cerberus_agents.tiny_canary_agent import TinyCanaryAgent
        
        agent = TinyCanaryAgent()
        self.assertIn("honeytokens", agent.config)
        self.assertIn("alert_channels", agent.config)


if __name__ == "__main__":
    unittest.main()
