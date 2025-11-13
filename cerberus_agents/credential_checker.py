#!/usr/bin/env python3
"""
Credential Checker

Checks password hygiene against local rules and common password lists.
Uses bcrypt for secure password hashing.

Usage:
    python -m cerberus_agents.credential_checker --users samples/users.csv.example
"""

import argparse
import json
import csv
import logging
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Dict
import re

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False
    logging.warning("bcrypt not available, using SHA256 instead")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CredentialChecker:
    def __init__(self, users_file: str, output_file: str = "credentials_audit.json"):
        self.users_file = Path(users_file)
        self.output_file = Path(output_file)
        self.common_passwords = self.load_common_passwords()
        self.audit_results = []
    
    def load_common_passwords(self) -> set:
        """Load common passwords list"""
        common_passwords_file = Path("config/common_passwords.txt")
        
        if common_passwords_file.exists():
            with common_passwords_file.open() as f:
                passwords = {line.strip().lower() for line in f if line.strip()}
            logger.info(f"✓ Loaded {len(passwords)} common passwords")
            return passwords
        else:
            logger.warning("⚠ common_passwords.txt not found, using default list")
            return {
                "password", "123456", "password123", "admin", "letmein",
                "welcome", "monkey", "dragon", "master", "qwerty",
                "abc123", "111111", "123123", "password1", "admin123"
            }
    
    def check_password_strength(self, password: str) -> Dict:
        """Check password against security rules"""
        issues = []
        score = 100
        
        if len(password) < 8:
            issues.append("Password too short (minimum 8 characters)")
            score -= 30
        elif len(password) < 12:
            issues.append("Password should be at least 12 characters")
            score -= 10
        
        if not re.search(r"[a-z]", password):
            issues.append("Missing lowercase letters")
            score -= 20
        
        if not re.search(r"[A-Z]", password):
            issues.append("Missing uppercase letters")
            score -= 20
        
        if not re.search(r"[0-9]", password):
            issues.append("Missing numbers")
            score -= 15
        
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            issues.append("Missing special characters")
            score -= 15
        
        if password.lower() in self.common_passwords:
            issues.append("⚠️ CRITICAL: Password found in common passwords list")
            score = 0
        
        sequential = ["123", "abc", "qwerty", "password"]
        if any(seq in password.lower() for seq in sequential):
            issues.append("Contains sequential or dictionary words")
            score -= 20
        
        score = max(0, score)
        
        if score >= 80:
            strength = "Strong"
        elif score >= 60:
            strength = "Moderate"
        elif score >= 40:
            strength = "Weak"
        else:
            strength = "Very Weak"
        
        return {
            "strength": strength,
            "score": score,
            "issues": issues
        }
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt or SHA256"""
        if BCRYPT_AVAILABLE:
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
            return hashed.decode('utf-8')
        else:
            salt = hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:16]
            hashed = hashlib.sha256((password + salt).encode()).hexdigest()
            return f"sha256${salt}${hashed}"
    
    def load_users(self) -> List[Dict]:
        """Load users from CSV file"""
        users = []
        
        if not self.users_file.exists():
            logger.error(f"❌ Users file not found: {self.users_file}")
            return users
        
        try:
            with self.users_file.open() as f:
                reader = csv.DictReader(f)
                for row in reader:
                    users.append(row)
            
            logger.info(f"✓ Loaded {len(users)} user accounts")
        except Exception as e:
            logger.error(f"❌ Error loading users: {e}")
        
        return users
    
    def audit_credentials(self):
        """Audit all credentials"""
        logger.info("=" * 60)
        logger.info("🛡️  CERBERUS CREDENTIAL CHECKER")
        logger.info("=" * 60)
        
        if not Path("config/allowed_targets.yml").exists():
            logger.error("❌ ABORTED: No authorization file (allowed_targets.yml) found")
            return
        
        logger.info("✓ Authorization verified")
        users = self.load_users()
        
        if not users:
            logger.error("❌ No users to audit")
            return
        
        logger.info(f"\n🔍 Auditing {len(users)} accounts...\n")
        
        weak_count = 0
        critical_count = 0
        
        for user in users:
            username = user.get("username", "unknown")
            password = user.get("password", "")
            
            strength_result = self.check_password_strength(password)
            
            password_hash = self.hash_password(password)
            
            audit_entry = {
                "username": username,
                "email": user.get("email", ""),
                "department": user.get("department", ""),
                "password_hash": password_hash,
                "strength": strength_result["strength"],
                "score": strength_result["score"],
                "issues": strength_result["issues"],
                "recommendations": []
            }
            
            if strength_result["score"] < 60:
                weak_count += 1
            
            if strength_result["score"] < 40:
                critical_count += 1
                audit_entry["recommendations"].append("⚠️ URGENT: Change password immediately")
            
            if strength_result["issues"]:
                audit_entry["recommendations"].append("Use a password manager to generate strong passwords")
                audit_entry["recommendations"].append("Enable multi-factor authentication (MFA)")
            
            logger.info(f"👤 {username}: {strength_result['strength']} (Score: {strength_result['score']}/100)")
            if strength_result["issues"]:
                for issue in strength_result["issues"]:
                    logger.info(f"   - {issue}")
            
            self.audit_results.append(audit_entry)
        
        summary = {
            "audit_date": datetime.now().isoformat(),
            "total_accounts": len(users),
            "weak_passwords": weak_count,
            "critical_passwords": critical_count,
            "audit_results": self.audit_results,
            "recommendations": [
                "Enforce minimum password length of 12 characters",
                "Require complexity (uppercase, lowercase, numbers, special chars)",
                "Implement password expiration policy (90 days)",
                "Enable multi-factor authentication for all accounts",
                "Use a password manager",
                "Regular security awareness training"
            ]
        }
        
        with self.output_file.open("w") as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"\n" + "=" * 60)
        logger.info("📊 AUDIT SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Total Accounts: {len(users)}")
        logger.info(f"Weak Passwords: {weak_count} ({weak_count/len(users)*100:.1f}%)")
        logger.info(f"Critical Issues: {critical_count} ({critical_count/len(users)*100:.1f}%)")
        logger.info(f"\n✅ Audit complete!")
        logger.info(f"📄 Results saved to: {self.output_file.absolute()}")


def main():
    parser = argparse.ArgumentParser(description="Credential Checker")
    parser.add_argument("--users", required=True, help="Path to users CSV file")
    parser.add_argument("--output", default="credentials_audit.json", help="Output JSON file")
    parser.add_argument('--authorized', action='store_true',
                       help='Confirm you have authorization to perform this action')
    args = parser.parse_args()
    
    checker = CredentialChecker(args.users, args.output)
    checker.audit_credentials()


if __name__ == "__main__":
    main()
