#!/usr/bin/env python3
"""
Automated test suite for Hash Chaining & Immutable Storage
Tests Phase 1, 2, and 3 of the append-only versioning system
"""

import requests
import json
import sys
from typing import Optional, Tuple
from hashlib import sha256

# Configuration
BASE_URL = "http://localhost:8000/api"
USERNAME = "testuser"
PASSWORD = "testpass123"
TOKEN = None
DOC_ID = None

class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    END = "\033[0m"

def log_pass(msg: str):
    print(f"{Colors.GREEN}✓ PASS:{Colors.END} {msg}")

def log_fail(msg: str):
    print(f"{Colors.RED}✗ FAIL:{Colors.END} {msg}")

def log_info(msg: str):
    print(f"{Colors.BLUE}ℹ INFO:{Colors.END} {msg}")

def log_warn(msg: str):
    print(f"{Colors.YELLOW}⚠ WARN:{Colors.END} {msg}")

def test_separator(title: str):
    print(f"\n{Colors.BLUE}{'='*60}")
    print(f"{title}")
    print(f"{'='*60}{Colors.END}\n")

# ============================================================================
# Phase 0: Setup & Authentication
# ============================================================================

def test_register() -> bool:
    """Test user registration"""
    test_separator("PHASE 0: Setup - Register User")
    
    try:
        response = requests.post(
            f"{BASE_URL}/register/",
            json={
                "username": USERNAME,
                "password": PASSWORD,
                "signature_algorithm": "RSA-SHA256"
            }
        )
        
        if response.status_code == 201:
            data = response.json()
            global TOKEN
            TOKEN = data.get("token")
            log_pass(f"User registered: {USERNAME}")
            log_pass(f"Token acquired: {TOKEN[:20]}...")
            return True
        elif response.status_code == 400 and "already taken" in response.text:
            log_warn(f"User {USERNAME} already exists")
            return test_login()
        else:
            log_fail(f"Registration failed: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        log_fail(f"Registration error: {e}")
        return False

def test_login() -> bool:
    """Test user login"""
    test_separator("PHASE 0: Setup - Login User")
    
    try:
        response = requests.post(
            f"{BASE_URL}/login/",
            json={
                "username": USERNAME,
                "password": PASSWORD
            }
        )
        
        if response.status_code == 200:
            data = response.json()
            global TOKEN
            TOKEN = data.get("token")
            log_pass(f"User logged in: {USERNAME}")
            log_pass(f"Token acquired: {TOKEN[:20]}...")
            return True
        else:
            log_fail(f"Login failed: {response.status_code}")
            return False
    except Exception as e:
        log_fail(f"Login error: {e}")
        return False

# ============================================================================
# Phase 1: Create First Document (GENESIS Anchor)
# ============================================================================

def test_sign_new_document() -> Tuple[bool, Optional[dict]]:
    """Test signing a new document (Phase 1)"""
    test_separator("PHASE 1: Create First Document - Sign New Document")
    
    try:
        response = requests.post(
            f"{BASE_URL}/sign-document/",
            headers={"Authorization": f"Token {TOKEN}"},
            files={"data": "Initial version - This is my document"}
        )
        
        if response.status_code == 200:
            data = response.json()
            global DOC_ID
            DOC_ID = data.get("document_id")
            
            # Validations
            checks = [
                ("document_id exists", "document_id" in data),
                ("version_no is 1", data.get("version_no") == "1"),
                ("prev_chain_hash is GENESIS", data.get("prev_chain_hash") == "GENESIS"),
                ("chain_hash exists", "chain_hash" in data and data.get("chain_hash")),
                ("signature exists", "signature" in data and data.get("signature")),
                ("hash exists", "hash" in data and data.get("hash")),
            ]
            
            all_pass = True
            for check_name, result in checks:
                if result:
                    log_pass(check_name)
                else:
                    log_fail(check_name)
                    all_pass = False
            
            log_info(f"Document ID: {DOC_ID}")
            log_info(f"Version: {data.get('version_no')}")
            log_info(f"Chain Hash: {data.get('chain_hash')[:16]}...")
            
            return all_pass, data
        else:
            log_fail(f"Sign failed: {response.status_code} - {response.text}")
            return False, None
    except Exception as e:
        log_fail(f"Sign error: {e}")
        return False, None

# ============================================================================
# Phase 2: Append New Versions
# ============================================================================

def test_add_version(version_num: int, content: str) -> Tuple[bool, Optional[dict]]:
    """Test adding a new version (Phase 2)"""
    test_separator(f"PHASE 2: Append Version {version_num}")
    
    try:
        response = requests.post(
            f"{BASE_URL}/add-document-version/",
            headers={"Authorization": f"Token {TOKEN}"},
            data={"document_id": DOC_ID},
            files={"data": content}
        )
        
        if response.status_code == 200:
            data = response.json()
            
            checks = [
                ("document_id matches", data.get("document_id") == DOC_ID),
                (f"version_no is {version_num}", data.get("version_no") == str(version_num)),
                ("prev_chain_hash exists", "prev_chain_hash" in data and data.get("prev_chain_hash")),
                ("prev_chain_hash not GENESIS", data.get("prev_chain_hash") != "GENESIS"),
                ("chain_hash exists", "chain_hash" in data and data.get("chain_hash")),
                ("new chain_hash differs from prev_chain_hash", 
                 data.get("chain_hash") != data.get("prev_chain_hash")),
            ]
            
            all_pass = True
            for check_name, result in checks:
                if result:
                    log_pass(check_name)
                else:
                    log_fail(check_name)
                    all_pass = False
            
            log_info(f"Version: {data.get('version_no')}")
            log_info(f"Prev Chain Hash: {data.get('prev_chain_hash')[:16]}...")
            log_info(f"Chain Hash: {data.get('chain_hash')[:16]}...")
            
            return all_pass, data
        else:
            log_fail(f"Add version failed: {response.status_code} - {response.text}")
            return False, None
    except Exception as e:
        log_fail(f"Add version error: {e}")
        return False, None

# ============================================================================
# Phase 3: Verify Chain Integrity
# ============================================================================

def test_verify_valid_chain(signed_package_file: str) -> Tuple[bool, Optional[dict]]:
    """Test verifying a valid chain (Phase 3)"""
    test_separator("PHASE 3: Verify Valid Chain Integrity")
    
    try:
        with open(signed_package_file, "rb") as f:
            response = requests.post(
                f"{BASE_URL}/verify-document/",
                files={"file": f}
            )
        
        if response.status_code == 200:
            data = response.json()
            chain_verification = data.get("chain_verification", {})
            
            checks = [
                ("status is valid", data.get("status") == "valid"),
                ("chain_verification.status is valid", chain_verification.get("status") == "valid"),
                ("broken_at_version is null", chain_verification.get("broken_at_version") is None),
                ("verified_versions > 0", chain_verification.get("verified_versions", 0) > 0),
            ]
            
            all_pass = True
            for check_name, result in checks:
                if result:
                    log_pass(check_name)
                else:
                    log_fail(check_name)
                    all_pass = False
            
            log_info(f"Chain Status: {chain_verification.get('status')}")
            log_info(f"Verified Versions: {chain_verification.get('verified_versions')}")
            log_info(f"Signature Status: {data.get('message')}")
            
            return all_pass, data
        else:
            log_fail(f"Verification failed: {response.status_code}")
            return False, None
    except Exception as e:
        log_fail(f"Verification error: {e}")
        return False, None

def test_detect_tampering(tamper_type: str, signed_package_file: str) -> Tuple[bool, Optional[dict]]:
    """Test detecting database tampering (Phase 3 - Advanced)"""
    test_separator(f"PHASE 3 ADVANCED: Detect Tampering - {tamper_type}")
    
    try:
        with open(signed_package_file, "rb") as f:
            response = requests.post(
                f"{BASE_URL}/verify-document/",
                files={"file": f}
            )
        
        if response.status_code == 200:
            data = response.json()
            chain_verification = data.get("chain_verification", {})
            
            # After tampering, we expect invalid chain
            checks = [
                ("chain_verification.status is invalid", 
                 chain_verification.get("status") == "invalid"),
                ("broken_at_version is not null", 
                 chain_verification.get("broken_at_version") is not None),
            ]
            
            all_pass = True
            for check_name, result in checks:
                if result:
                    log_pass(check_name)
                else:
                    log_fail(check_name)
                    all_pass = False
            
            log_info(f"Chain Status: {chain_verification.get('status')}")
            log_info(f"Broken At Version: {chain_verification.get('broken_at_version')}")
            log_info(f"Verified Versions: {chain_verification.get('verified_versions')}")
            
            return all_pass, data
        else:
            log_fail(f"Verification failed: {response.status_code}")
            return False, None
    except Exception as e:
        log_fail(f"Verification error: {e}")
        return False, None

# ============================================================================
# Database Introspection
# ============================================================================

def test_database_chain_validation() -> bool:
    """Test chain validation by inspecting database directly"""
    test_separator("DATABASE: Validate Chain Links")
    
    try:
        # This would need to be implemented with Django shell or API endpoint
        # For now, we'll provide guidance
        log_info("Run in Django shell: python manage.py shell")
        log_info("Then execute the following:")
        print("""
from api.models import DocumentRecord, DocumentVersion

record = DocumentRecord.objects.get(doc_id='{doc_id}')
versions = list(record.versions.order_by('version_no'))

for i, v in enumerate(versions):
    print(f"\\nVersion {{i+1}}:")
    print(f"  prev_chain_hash: {{v.prev_chain_hash}}")
    print(f"  chain_hash: {{v.chain_hash}}")

# Verify links
print("\\n--- Chain Links ---")
for i in range(1, len(versions)):
    prev_v = versions[i-1]
    curr_v = versions[i]
    match = prev_v.chain_hash == curr_v.prev_chain_hash
    symbol = "✓" if match else "✗"
    print(f"V{{i}} → V{{i+1}}: {{symbol}}")
        """.format(doc_id=DOC_ID))
        
        return True
    except Exception as e:
        log_fail(f"Database validation error: {e}")
        return False

# ============================================================================
# Main Test Suite
# ============================================================================

def main():
    print(f"\n{Colors.BLUE}{'='*60}")
    print("HASH CHAINING & IMMUTABLE STORAGE TEST SUITE")
    print(f"{'='*60}{Colors.END}\n")
    
    results = {}
    v2_data = None
    v3_data = None
    
    # Phase 0: Setup
    results["register"] = test_register()
    
    # Phase 1: Create first document
    phase1_pass, phase1_data = test_sign_new_document()
    results["phase1_sign"] = phase1_pass
    
    if not phase1_pass or not phase1_data:
        log_fail("Cannot proceed - Phase 1 failed")
        return
    
    # Save signed document
    with open("signed_v1.json", "w") as f:
        json.dump(phase1_data, f, indent=2)
    log_info("Saved: signed_v1.json")
    
    # Phase 2: Add versions
    phase2_v2_pass, v2_data = test_add_version(2, "Updated version - Added more content")
    results["phase2_v2"] = phase2_v2_pass
    
    with open("signed_v2.json", "w") as f:
        json.dump(v2_data, f, indent=2)
    log_info("Saved: signed_v2.json")
    
    phase2_v3_pass, v3_data = test_add_version(3, "Final version - Completed")
    results["phase2_v3"] = phase2_v3_pass
    
    with open("signed_v3.json", "w") as f:
        json.dump(v3_data, f, indent=2)
    log_info("Saved: signed_v3.json")
    
    # Phase 3: Verify valid chain
    phase3_verify_pass, phase3_data = test_verify_valid_chain("signed_v3.json")
    results["phase3_verify"] = phase3_verify_pass
    
    # Print summary
    test_separator("TEST SUMMARY")
    total_tests = len(results)
    passed_tests = sum(1 for v in results.values() if v)
    
    print(f"Tests Passed: {Colors.GREEN}{passed_tests}{Colors.END}/{total_tests}\n")
    
    for test_name, result in results.items():
        status = f"{Colors.GREEN}PASS{Colors.END}" if result else f"{Colors.RED}FAIL{Colors.END}"
        print(f"  {test_name}: {status}")
    
    if passed_tests == total_tests:
        print(f"\n{Colors.GREEN}✓ All tests passed!{Colors.END}")
        print(f"\n{Colors.YELLOW}Next steps:{Colors.END}")
        print("  1. Test database tampering (see TEST_HASH_CHAIN.md)")
        print("  2. Manually modify database records and re-verify")
        print("  3. Confirm broken_at_version detection works")
    else:
        print(f"\n{Colors.RED}✗ Some tests failed{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()
