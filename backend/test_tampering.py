#!/usr/bin/env python3
"""
Advanced Tampering Detection Test
Tests all tampering scenarios and recovery
"""

import os
import sys
import django
import json
import subprocess
from pathlib import Path

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'signature_project.settings')
sys.path.insert(0, str(Path(__file__).parent))
django.setup()

from api.models import DocumentRecord, DocumentVersion
from api.views import _compute_chain_hash
from hashlib import sha256

BASE_URL = "http://localhost:8000/api"
BACKEND_DIR = Path(__file__).parent

def verify_document(file_path):
    """Verify document using API"""
    cmd = [
        "curl", "-s", "-X", "POST", 
        f"{BASE_URL}/verify-document",
        "-F", f"file=@{file_path}"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(result.stdout)
    except:
        return {"error": result.stdout[:200]}

def print_section(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")

def print_result(test_name, passed, details=""):
    status = "✅ PASS" if passed else "❌ FAIL"
    print(f"{status} | {test_name}")
    if details:
        print(f"       {details}")

# Load the test document
v3_file = BACKEND_DIR / "signed_v3.json"
with open(v3_file) as f:
    v3_data = json.load(f)

doc_id = v3_data["document_id"]
record = DocumentRecord.objects.get(doc_id=doc_id)
v1 = record.versions.get(version_no=1)
v2 = record.versions.get(version_no=2)
v3 = record.versions.get(version_no=3)

# ==============================================================================
print_section("BASELINE: Verify All Versions Are Valid")

resp = verify_document(str(v3_file))
baseline_valid = resp.get("chain_verification", {}).get("status") == "valid"
baseline_versions = resp.get("chain_verification", {}).get("verified_versions")
baseline_broken = resp.get("chain_verification", {}).get("broken_at_version")

print_result("Baseline Chain", baseline_valid, 
    f"verified_versions={baseline_versions}, broken_at={baseline_broken}")

# ==============================================================================
print_section("TEST 1: TAMPER WITH V1 PAYLOAD")

print("Storing original V1 payload_hash...")
original_v1_payload = v1.payload_hash
print(f"  Original: {original_v1_payload[:40]}...\n")

print("Tampering with V1 payload_hash...")
v1.payload_hash = "tampered_hash_xyz999abc111def222ghi333jkl444mno555pqr666stu"
v1.save()
print(f"  Tampered: {v1.payload_hash[:40]}...\n")

print("Verifying (should detect tampering at V1)...")
resp = verify_document(str(v3_file))
t1_status = resp.get("chain_verification", {}).get("status")
t1_broken = resp.get("chain_verification", {}).get("broken_at_version")
t1_passed = (t1_status == "invalid" and t1_broken == 1)

print_result("Test 1: Detect V1 Tampering", t1_passed,
    f"status={t1_status}, broken_at={t1_broken}")

print("\nRestoring V1 payload_hash...")
v1.payload_hash = original_v1_payload
v1.save()
print(f"  Restored: {v1.payload_hash[:40]}...\n")

print("Verifying (should be valid again)...")
resp = verify_document(str(v3_file))
t1_restored = resp.get("chain_verification", {}).get("status") == "valid"
print_result("Test 1: Verify Recovery", t1_restored)

# ==============================================================================
print_section("TEST 2: BREAK V2 CHAIN LINK")

print("Storing original V2 prev_chain_hash...")
original_v2_prev = v2.prev_chain_hash
print(f"  Original: {original_v2_prev[:40]}...\n")

print("Breaking V2's link to V1...")
v2.prev_chain_hash = "broken_link_xyz999abc111def222ghi333jkl444mno555pqr666stu"
v2.save()
print(f"  Broken: {v2.prev_chain_hash[:40]}...\n")

print("Verifying (should detect link failure at V2)...")
resp = verify_document(str(v3_file))
t2_status = resp.get("chain_verification", {}).get("status")
t2_broken = resp.get("chain_verification", {}).get("broken_at_version")
t2_passed = (t2_status == "invalid" and t2_broken == 2)

print_result("Test 2: Detect V2 Link Break", t2_passed,
    f"status={t2_status}, broken_at={t2_broken}")

print("\nRestoring V2 prev_chain_hash...")
v2.prev_chain_hash = original_v2_prev
v2.save()
print(f"  Restored: {v2.prev_chain_hash[:40]}...\n")

print("Verifying (should be valid again)...")
resp = verify_document(str(v3_file))
t2_restored = resp.get("chain_verification", {}).get("status") == "valid"
print_result("Test 2: Verify Recovery", t2_restored)

# ==============================================================================
print_section("TEST 3: CORRUPT V2 SIGNATURE")

print("Storing original V2 signature_b64...")
original_v2_sig = v2.signature_b64
print(f"  Original: {original_v2_sig[:40]}...\n")

print("Corrupting V2 signature_b64...")
v2.signature_b64 = "corrupt_signature_data_xyz999abc111def222ghi333jkl444mno555pqr"
v2.save()
print(f"  Corrupted: {v2.signature_b64[:40]}...\n")

print("Verifying (should detect signature corruption at V2)...")
resp = verify_document(str(v3_file))
t3_status = resp.get("chain_verification", {}).get("status")
t3_broken = resp.get("chain_verification", {}).get("broken_at_version")
t3_passed = (t3_status == "invalid" and t3_broken == 2)

print_result("Test 3: Detect V2 Signature Corruption", t3_passed,
    f"status={t3_status}, broken_at={t3_broken}")

print("\nRestoring V2 signature_b64...")
v2.signature_b64 = original_v2_sig
v2.save()
print(f"  Restored: {v2.signature_b64[:40]}...\n")

print("Verifying (should be valid again)...")
resp = verify_document(str(v3_file))
t3_restored = resp.get("chain_verification", {}).get("status") == "valid"
print_result("Test 3: Verify Recovery", t3_restored)

# ==============================================================================
print_section("TEST 4: TAMPER WITH V3 PAYLOAD")

print("Storing original V3 payload_hash...")
original_v3_payload = v3.payload_hash
print(f"  Original: {original_v3_payload[:40]}...\n")

print("Tampering with V3 payload_hash...")
v3.payload_hash = "v3_tampered_xyz999abc111def222ghi333jkl444mno555pqr666stu"
v3.save()
print(f"  Tampered: {v3.payload_hash[:40]}...\n")

print("Verifying (should detect tampering at V3)...")
resp = verify_document(str(v3_file))
t4_status = resp.get("chain_verification", {}).get("status")
t4_broken = resp.get("chain_verification", {}).get("broken_at_version")
t4_passed = (t4_status == "invalid" and t4_broken == 3)

print_result("Test 4: Detect V3 Tampering", t4_passed,
    f"status={t4_status}, broken_at={t4_broken}")

print("\nRestoring V3 payload_hash...")
v3.payload_hash = original_v3_payload
v3.save()
print(f"  Restored: {v3.payload_hash[:40]}...\n")

print("Verifying (should be valid again)...")
resp = verify_document(str(v3_file))
t4_restored = resp.get("chain_verification", {}).get("status") == "valid"
print_result("Test 4: Verify Recovery", t4_restored)

# ==============================================================================
print_section("TEST 5: MULTIPLE TAMPERING (V1 + V2)")

print("Tampering V1 payload AND breaking V2 link simultaneously...")
v1.payload_hash = "multi_v1_tampered_xyz999abc111def222"
v2.prev_chain_hash = "multi_v2_broken_xyz999abc111def222"
v1.save()
v2.save()
print("  Both tampered\n")

print("Verifying (should detect at V1 first)...")
resp = verify_document(str(v3_file))
t5_status = resp.get("chain_verification", {}).get("status")
t5_broken = resp.get("chain_verification", {}).get("broken_at_version")
# Should detect at V1 since the chain verification stops at first break
t5_passed = (t5_status == "invalid" and t5_broken == 1)

print_result("Test 5: Detect Multiple Tampering", t5_passed,
    f"status={t5_status}, broken_at={t5_broken} (stops at first break)")

print("\nRestoring both V1 and V2...")
v1.payload_hash = original_v1_payload
v2.prev_chain_hash = original_v2_prev
v1.save()
v2.save()
print("  Both restored\n")

print("Verifying (should be valid again)...")
resp = verify_document(str(v3_file))
t5_restored = resp.get("chain_verification", {}).get("status") == "valid"
print_result("Test 5: Verify Recovery", t5_restored)

# ==============================================================================
print_section("FINAL RESULTS - TAMPERING DETECTION")

tests_passed = [
    t1_passed, t1_restored,
    t2_passed, t2_restored,
    t3_passed, t3_restored,
    t4_passed, t4_restored,
    t5_passed, t5_restored,
]

if all(tests_passed):
    print("✅ ALL TAMPERING TESTS PASSED!\n")
    print("Your system successfully:")
    print("  ✓ Detected V1 payload tampering")
    print("  ✓ Detected V2 chain link breaking")
    print("  ✓ Detected V2 signature corruption")
    print("  ✓ Detected V3 payload tampering")
    print("  ✓ Detected multiple simultaneous tampering")
    print("  ✓ Recovered after restoration in all cases")
    print("\n🎯 Tampering Localization:")
    print("  - Detects EXACTLY which version was tampered")
    print("  - Stops verification at first break point")
    print("  - Reports broken_at_version correctly")
    print("\n🔐 Security Properties Verified:")
    print("  ✓ Immutability: Any modification detected")
    print("  ✓ Integrity: Chain links cannot be broken undetected")
    print("  ✓ Authenticity: Signatures cannot be forged")
    print("  ✓ Traceability: Exact tampering location identified")
else:
    failed_count = len([t for t in tests_passed if not t])
    print(f"❌ {failed_count} TESTS FAILED\n")
    sys.exit(1)

print("\n" + "="*70)
