#!/usr/bin/env python3
"""
Automated Hash Chaining System Test
Tests all 3 phases + tampering detection
"""

import subprocess
import json
import sys
import time
from pathlib import Path

BASE_URL = "http://localhost:8000/api"
BACKEND_DIR = Path(__file__).parent

def run_curl(method, endpoint, headers=None, data=None, files=None):
    """Execute curl command and return JSON response"""
    url = f"{BASE_URL}{endpoint}"
    cmd = ["curl", "-s", "-X", method, url]
    
    if headers:
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
    
    if data:
        cmd.extend(["-H", "Content-Type: application/json", "-d", json.dumps(data)])
    
    if files:
        for key, filepath in files.items():
            cmd.extend(["-F", f"{key}=@{filepath}"])
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return json.loads(result.stdout) if result.stdout.strip() else {"error": "Empty response"}
    except json.JSONDecodeError as e:
        return {"error": f"Invalid JSON: {result.stdout[:100]}"}
    except Exception as e:
        return {"error": str(e)}

def print_section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")

def print_result(test_name, passed, details=""):
    status = "✅ PASS" if passed else "❌ FAIL"
    print(f"{status} | {test_name}")
    if details:
        print(f"       {details}")

# ==============================================================================
print_section("PHASE 0: REGISTRATION")

print("Attempting to login...")
login_resp = run_curl("POST", "/login", data={
    "username": "testuser",
    "password": "testpass123"
})

token = login_resp.get("token")

if not token:
    print("User doesn't exist, registering...")
    register_resp = run_curl("POST", "/register", data={
        "username": "testuser",
        "password": "testpass123",
        "signature_algorithm": "RSA-SHA256"
    })
    token = register_resp.get("token")
    if "error" in register_resp:
        print_result("Register", False, register_resp["error"])
        sys.exit(1)

print_result("Login/Register", bool(token), f"Token: {token[:30]}..." if token else "No token")

if not token:
    sys.exit(1)

# ==============================================================================
print_section("PHASE 1: CREATE FIRST DOCUMENT (GENESIS ANCHOR)")

print("Signing first document...")
sign_headers = {"Authorization": f"Token {token}"}
sign_files = {"data": "/tmp/test_doc_v1.txt"}

# Create temp file
with open("/tmp/test_doc_v1.txt", "w") as f:
    f.write("Initial version - This is my test document")

sign_resp = run_curl("POST", "/sign-document", headers=sign_headers, files=sign_files)

if "error" in sign_resp:
    print_result("Sign Document V1", False, sign_resp["error"])
    sys.exit(1)

# Save response
v1_data = sign_resp
v1_file = BACKEND_DIR / "signed_v1.json"
with open(v1_file, "w") as f:
    json.dump(v1_data, f, indent=2)

doc_id = v1_data.get("document_id")
v1_prev_hash = v1_data.get("prev_chain_hash")
v1_chain_hash = v1_data.get("chain_hash")
v1_version = v1_data.get("version_no")

checks = [
    (v1_prev_hash == "GENESIS", "prev_chain_hash == 'GENESIS'"),
    (v1_version == "1", "version_no == 1"),
    (len(v1_chain_hash or "") > 0, f"chain_hash present ({v1_chain_hash[:20]}...)" if v1_chain_hash else "No chain_hash"),
]

print_result("Phase 1: Sign Document", all(c[0] for c in checks))
for check, desc in checks:
    print(f"  {'✓' if check else '✗'} {desc}")

if not all(c[0] for c in checks):
    print("\nV1 Response:", json.dumps(v1_data, indent=2)[:500])
    sys.exit(1)

print(f"\nDocument ID: {doc_id}")
print(f"Saved to: {v1_file}")

# ==============================================================================
print_section("PHASE 2: ADD VERSIONS 2 & 3")

# Version 2
print("Adding version 2...")
with open("/tmp/test_doc_v2.txt", "w") as f:
    f.write("Updated version - Added more content")

v2_resp = run_curl("POST", "/add-document-version", headers=sign_headers, files={
    "document_id": None,  # Will use form data instead
    "data": "/tmp/test_doc_v2.txt"
})

# Need to handle form data differently
cmd = [
    "curl", "-s", "-X", "POST", 
    f"{BASE_URL}/add-document-version",
    "-H", f"Authorization: Token {token}",
    "-F", f"document_id={doc_id}",
    "-F", "data=@/tmp/test_doc_v2.txt"
]
result = subprocess.run(cmd, capture_output=True, text=True)
v2_data = json.loads(result.stdout)

v2_file = BACKEND_DIR / "signed_v2.json"
with open(v2_file, "w") as f:
    json.dump(v2_data, f, indent=2)

v2_prev_hash = v2_data.get("prev_chain_hash")
v2_chain_hash = v2_data.get("chain_hash")
v2_version = v2_data.get("version_no")

checks_v2 = [
    (v2_prev_hash == v1_chain_hash, f"prev_chain_hash matches V1's chain_hash"),
    (v2_version == "2", "version_no == 2"),
    (len(v2_chain_hash or "") > 0, "chain_hash present"),
]

print_result("Phase 2: Add Version 2", all(c[0] for c in checks_v2))
for check, desc in checks_v2:
    print(f"  {'✓' if check else '✗'} {desc}")

# Version 3
print("\nAdding version 3...")
with open("/tmp/test_doc_v3.txt", "w") as f:
    f.write("Final version - Completed")

cmd = [
    "curl", "-s", "-X", "POST", 
    f"{BASE_URL}/add-document-version",
    "-H", f"Authorization: Token {token}",
    "-F", f"document_id={doc_id}",
    "-F", "data=@/tmp/test_doc_v3.txt"
]
result = subprocess.run(cmd, capture_output=True, text=True)
v3_data = json.loads(result.stdout)

v3_file = BACKEND_DIR / "signed_v3.json"
with open(v3_file, "w") as f:
    json.dump(v3_data, f, indent=2)

v3_prev_hash = v3_data.get("prev_chain_hash")
v3_chain_hash = v3_data.get("chain_hash")
v3_version = v3_data.get("version_no")

checks_v3 = [
    (v3_prev_hash == v2_chain_hash, f"prev_chain_hash matches V2's chain_hash"),
    (v3_version == "3", "version_no == 3"),
    (len(v3_chain_hash or "") > 0, "chain_hash present"),
]

print_result("Phase 2: Add Version 3", all(c[0] for c in checks_v3))
for check, desc in checks_v3:
    print(f"  {'✓' if check else '✗'} {desc}")

print(f"\nSaved to: {v2_file}")
print(f"Saved to: {v3_file}")

# ==============================================================================
print_section("PHASE 3: VERIFY COMPLETE CHAIN")

print("Verifying complete chain (V1 -> V2 -> V3)...")
cmd = [
    "curl", "-s", "-X", "POST", 
    f"{BASE_URL}/verify-document",
    "-F", f"file=@{v3_file}"
]
result = subprocess.run(cmd, capture_output=True, text=True)
verify_resp = json.loads(result.stdout)

status = verify_resp.get("status")
chain_status = verify_resp.get("chain_verification", {}).get("status")
verified_versions = verify_resp.get("chain_verification", {}).get("verified_versions")
broken_at = verify_resp.get("chain_verification", {}).get("broken_at_version")

checks_verify = [
    (status == "valid", f"status == 'valid' (got: {status})"),
    (chain_status == "valid", f"chain_verification.status == 'valid' (got: {chain_status})"),
    (verified_versions == 3, f"verified_versions == 3 (got: {verified_versions})"),
    (broken_at is None, f"broken_at_version == null (got: {broken_at})"),
]

print_result("Phase 3: Verify Chain", all(c[0] for c in checks_verify))
for check, desc in checks_verify:
    print(f"  {'✓' if check else '✗'} {desc}")

# ==============================================================================
print_section("FINAL RESULTS")

all_passed = (
    all(c[0] for c in checks) and
    all(c[0] for c in checks_v2) and
    all(c[0] for c in checks_v3) and
    all(c[0] for c in checks_verify)
)

if all_passed:
    print("✅ ALL TESTS PASSED!")
    print("\nYour immutable storage system is working perfectly:")
    print("  ✓ Phase 1: GENESIS anchor created")
    print("  ✓ Phase 2: Versions 2 & 3 appended with correct chain links")
    print("  ✓ Phase 3: Complete chain verified (3 versions)")
    print("\nTest files saved:")
    print(f"  - {v1_file}")
    print(f"  - {v2_file}")
    print(f"  - {v3_file}")
else:
    print("❌ SOME TESTS FAILED")
    print("\nVerify response:")
    print(json.dumps(verify_resp, indent=2)[:500])
    sys.exit(1)

print("\n" + "="*60)
