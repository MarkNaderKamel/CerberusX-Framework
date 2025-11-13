#!/usr/bin/env python3
"""
Garak - AI/LLM Red Teaming Tool
100+ adversarial attack modules for Large Language Models
Prompt injection, jailbreaking, data extraction
"""

import subprocess
import json
import logging
import os
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class GarakAIRedTeam:
    """
    Garak - LLM Vulnerability Scanner
    Production-ready AI red teaming framework
    """
    
    def __init__(self):
        self.garak_installed = self._check_garak()
        
    def _check_garak(self) -> bool:
        """Check if Garak is installed"""
        result = subprocess.run(["which", "garak"], capture_output=True)
        return result.returncode == 0
    
    def install_garak(self) -> Dict[str, any]:
        """Install Garak AI red teaming tool"""
        logger.info("Installing Garak...")
        
        try:
            result = subprocess.run(
                ["pip3", "install", "garak"],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                self.garak_installed = True
                return {
                    "success": True,
                    "message": "Garak installed successfully"
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr
                }
                
        except Exception as e:
            logger.error(f"Installation failed: {e}")
            return {"success": False, "error": str(e)}
    
    def scan_model(self, model_type: str, model_name: str, 
                   probes: str = "all", api_key: Optional[str] = None) -> Dict[str, any]:
        """
        Scan LLM for vulnerabilities
        
        Args:
            model_type: Model type (openai, huggingface, anthropic, etc.)
            model_name: Model name (gpt-4, claude-3, etc.)
            probes: Probe types (all, prompt_injection, jailbreak, etc.)
            api_key: API key for model access
        """
        if not self.garak_installed:
            return {"success": False, "error": "Garak not installed"}
        
        logger.info(f"Scanning {model_type}:{model_name} with probes: {probes}")
        
        try:
            cmd = [
                "garak",
                "--model_type", model_type,
                "--model_name", model_name,
                "--probes", probes
            ]
            
            if api_key:
                env = os.environ.copy()
                if model_type == "openai":
                    env["OPENAI_API_KEY"] = api_key
                elif model_type == "anthropic":
                    env["ANTHROPIC_API_KEY"] = api_key
            else:
                env = None
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
                env=env
            )
            
            return {
                "success": True,
                "message": f"Scan completed for {model_type}:{model_name}",
                "output": result.stdout,
                "model_type": model_type,
                "model_name": model_name,
                "probes": probes
            }
            
        except Exception as e:
            logger.error(f"Model scan failed: {e}")
            return {"success": False, "error": str(e)}
    
    def prompt_injection_test(self, model_type: str, model_name: str,
                             api_key: Optional[str] = None) -> Dict[str, any]:
        """
        Test for prompt injection vulnerabilities
        
        Args:
            model_type: Model type
            model_name: Model name
            api_key: API key
        """
        logger.info(f"Testing prompt injection: {model_type}:{model_name}")
        
        return self.scan_model(model_type, model_name, "promptinject", api_key)
    
    def jailbreak_test(self, model_type: str, model_name: str,
                      api_key: Optional[str] = None) -> Dict[str, any]:
        """
        Test for jailbreak vulnerabilities
        
        Args:
            model_type: Model type
            model_name: Model name
            api_key: API key
        """
        logger.info(f"Testing jailbreaks: {model_type}:{model_name}")
        
        return self.scan_model(model_type, model_name, "dan,aim", api_key)
    
    def data_extraction_test(self, model_type: str, model_name: str,
                            api_key: Optional[str] = None) -> Dict[str, any]:
        """
        Test for data extraction vulnerabilities
        
        Args:
            model_type: Model type
            model_name: Model name
            api_key: API key
        """
        logger.info(f"Testing data extraction: {model_type}:{model_name}")
        
        return self.scan_model(model_type, model_name, "leakreplay,divergence", api_key)
    
    def toxicity_test(self, model_type: str, model_name: str,
                     api_key: Optional[str] = None) -> Dict[str, any]:
        """
        Test for toxic output generation
        
        Args:
            model_type: Model type
            model_name: Model name
            api_key: API key
        """
        logger.info(f"Testing toxicity: {model_type}:{model_name}")
        
        return self.scan_model(model_type, model_name, "toxicity", api_key)
    
    def hallucination_test(self, model_type: str, model_name: str,
                          api_key: Optional[str] = None) -> Dict[str, any]:
        """
        Test for hallucination vulnerabilities
        
        Args:
            model_type: Model type
            model_name: Model name
            api_key: API key
        """
        logger.info(f"Testing hallucinations: {model_type}:{model_name}")
        
        return self.scan_model(model_type, model_name, "hallucination", api_key)
    
    def list_probes(self) -> Dict[str, any]:
        """List available attack probes"""
        if not self.garak_installed:
            return {"success": False, "error": "Garak not installed"}
        
        try:
            result = subprocess.run(
                ["garak", "--list_probes"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return {
                "success": True,
                "probes": result.stdout
            }
            
        except Exception as e:
            logger.error(f"Probe listing failed: {e}")
            return {"success": False, "error": str(e)}
    
    def get_attack_categories(self) -> List[Dict[str, str]]:
        """Get attack categories"""
        categories = [
            {
                "category": "Prompt Injection",
                "description": "Tests for prompt injection vulnerabilities",
                "probes": "promptinject"
            },
            {
                "category": "Jailbreaking",
                "description": "DAN, AIM, and other jailbreak techniques",
                "probes": "dan,aim,gcg"
            },
            {
                "category": "Data Extraction",
                "description": "Extract training data or sensitive info",
                "probes": "leakreplay,divergence"
            },
            {
                "category": "Toxicity",
                "description": "Generate toxic, harmful, or biased content",
                "probes": "toxicity"
            },
            {
                "category": "Hallucination",
                "description": "Force model to hallucinate false information",
                "probes": "hallucination"
            },
            {
                "category": "Security",
                "description": "Security-related vulnerabilities",
                "probes": "malwaregen,knownbadsignatures"
            },
            {
                "category": "Encoding",
                "description": "Encoding-based attacks (Base64, ROT13, etc.)",
                "probes": "encoding"
            }
        ]
        
        return categories


def demonstrate_garak():
    """Demonstrate Garak AI red teaming capabilities"""
    print("\n" + "="*70)
    print("GARAK - AI/LLM RED TEAMING FRAMEWORK")
    print("="*70)
    
    garak = GarakAIRedTeam()
    
    print("\n[*] Production Features:")
    print("    ✓ 100+ adversarial attack modules")
    print("    ✓ Prompt injection testing")
    print("    ✓ Jailbreak techniques (DAN, AIM, etc.)")
    print("    ✓ Data extraction attacks")
    print("    ✓ Toxicity and bias testing")
    print("    ✓ Hallucination detection")
    print("    ✓ MITRE ATLAS framework mapping")
    
    print("\n[*] Supported Models:")
    print("    • OpenAI (GPT-3.5, GPT-4)")
    print("    • Anthropic (Claude)")
    print("    • HuggingFace models")
    print("    • Google (PaLM)")
    print("    • Local models (llama.cpp, ggml)")
    
    print("\n[*] Attack Categories:")
    for category in garak.get_attack_categories():
        print(f"    • {category['category']}: {category['description']}")
    
    print("\n[*] Usage Examples:")
    print("    Full scan: garak.scan_model('openai', 'gpt-4', 'all', api_key)")
    print("    Prompt injection: garak.prompt_injection_test('openai', 'gpt-4', api_key)")
    print("    Jailbreak: garak.jailbreak_test('openai', 'gpt-4', api_key)")
    print("    Data extraction: garak.data_extraction_test('openai', 'gpt-4', api_key)")
    
    print("\n[*] Command Line:")
    print("    garak --model_type openai --model_name gpt-4 --probes all")
    
    print("\n[!] Authorization Required: Only test models you own or have permission to test")
    print("="*70)


if __name__ == "__main__":
    demonstrate_garak()
