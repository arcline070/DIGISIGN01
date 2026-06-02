"""
End-to-end tests for the Digital Signature System.
Tests: register, sign (text + file), verify (success + tamper detection).
"""
import json
import base64
import requests
import tempfile
import os

BASE = "http://127.0.0.1:8000/api"

def test_all():
    print("=" * 60)
    print("DIGITAL SIGNATURE SYSTEM — E2E TEST SUITE")
    print("=" * 60)
    
    # 1. Register a test user
    print("\n[1] Register test user...")
    resp = requests.post(f"{BASE}/register", json={
        "username": "testuser_e2e",
        "password": "TestPass123!"
    })
    if resp.status_code == 400 and "already taken" in resp.text:
        print("  User exists — logging in instead.")
        resp = requests.post(f"{BASE}/login", json={
            "username": "testuser_e2e",
            "password": "TestPass123!"
        })
    assert resp.status_code in (200, 201), f"Auth failed: {resp.status_code} {resp.text}"
    token = resp.json()["token"]
    headers = {"Authorization": f"Token {token}"}
    print(f"  ✔ Authenticated (token={token[:8]}...)")

    # 2. Sign TEXT data
    print("\n[2] Sign text data...")
    resp = requests.post(f"{BASE}/sign", json={"data": "Hello World"}, headers=headers)
    assert resp.status_code == 200, f"Sign text failed: {resp.status_code} {resp.text}"
    sign_result = resp.json()
    assert "signature" in sign_result
    assert "public_key" in sign_result
    assert "username" in sign_result
    print(f"  ✔ Signature: {sign_result['signature'][:40]}...")
    print(f"  ✔ Public key returned: {'-----BEGIN' in sign_result['public_key']}")
    print(f"  ✔ Username: {sign_result['username']}")
    
    # 3. Verify TEXT data — should SUCCEED
    print("\n[3] Verify text data (valid)...")
    resp = requests.post(f"{BASE}/verify", json={
        "data": "Hello World",
        "signature": sign_result["signature"],
        "public_key": sign_result["public_key"],
    }, headers=headers)
    assert resp.status_code == 200, f"Verify text failed: {resp.status_code} {resp.text}"
    assert resp.json()["status"] == "success", f"Expected success: {resp.json()}"
    print(f"  ✔ Verification result: {resp.json()['status']}")

    # 4. Verify with MODIFIED data — should FAIL
    print("\n[4] Verify tampered data (should fail)...")
    resp = requests.post(f"{BASE}/verify", json={
        "data": "Hello World TAMPERED",
        "signature": sign_result["signature"],
        "public_key": sign_result["public_key"],
    }, headers=headers)
    assert resp.json()["status"] == "failed", f"Expected failed: {resp.json()}"
    print(f"  ✔ Tampered data detected: {resp.json()['status']}")

    # 5. Verify with MODIFIED signature — should FAIL
    print("\n[5] Verify modified signature (should fail)...")
    bad_sig = base64.b64encode(b"fake_signature").decode()
    resp = requests.post(f"{BASE}/verify", json={
        "data": "Hello World",
        "signature": bad_sig,
        "public_key": sign_result["public_key"],
    }, headers=headers)
    assert resp.json()["status"] == "failed", f"Expected failed: {resp.json()}"
    print(f"  ✔ Modified signature detected: {resp.json()['status']}")

    # 6. Sign FILE
    print("\n[6] Sign file...")
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
        f.write("File content for signing test")
        tmp_path = f.name
    
    try:
        with open(tmp_path, "rb") as f:
            resp = requests.post(f"{BASE}/sign-document", files={"file": ("test.txt", f)}, headers=headers)
        assert resp.status_code == 200, f"Sign file failed: {resp.status_code} {resp.text}"
        signed_package = resp.json()
        assert "document" in signed_package
        assert "signature" in signed_package
        assert "public_key" in signed_package
        print(f"  ✔ File signed successfully")
        print(f"  ✔ Package keys: {list(signed_package.keys())}")
    finally:
        os.unlink(tmp_path)

    # 7. Verify signed file package
    print("\n[7] Verify signed file package (valid)...")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        json.dump(signed_package, f)
        pkg_path = f.name
    
    try:
        with open(pkg_path, "rb") as f:
            resp = requests.post(f"{BASE}/verify-document", files={"file": ("signed.json", f)}, headers=headers)
        assert resp.status_code == 200, f"Verify file failed: {resp.status_code} {resp.text}"
        verify_result = resp.json()
        assert verify_result["status"] == "valid", f"Expected valid: {verify_result}"
        print(f"  ✔ File verification: {verify_result['status']}")
        print(f"  ✔ Signed by: {verify_result.get('signed_by', 'N/A')}")
    finally:
        os.unlink(pkg_path)

    # 8. Tamper with document in package — should FAIL
    print("\n[8] Verify tampered file package (should fail)...")
    tampered = signed_package.copy()
    tampered["document"] = base64.b64encode(b"TAMPERED CONTENT").decode()
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        json.dump(tampered, f)
        tampered_path = f.name
    
    try:
        with open(tampered_path, "rb") as f:
            resp = requests.post(f"{BASE}/verify-document", files={"file": ("signed.json", f)}, headers=headers)
        assert resp.json()["status"] == "invalid", f"Expected invalid: {resp.json()}"
        print(f"  ✔ Tampered file detected: {resp.json()['status']}")
    finally:
        os.unlink(tampered_path)

    # 9. Check same key used across calls (one key per user)
    print("\n[9] Verify consistent key per user...")
    resp2 = requests.post(f"{BASE}/sign", json={"data": "Second sign"}, headers=headers)
    assert resp2.status_code == 200
    assert resp2.json()["public_key"] == sign_result["public_key"], "Key changed between calls!"
    print(f"  ✔ Same public key across both sign calls")

    # 10. Check my-public-key endpoint
    print("\n[10] Check my-public-key endpoint...")
    resp = requests.get(f"{BASE}/my-public-key", headers=headers)
    assert resp.status_code == 200
    pk_result = resp.json()
    assert "public_key" in pk_result
    assert pk_result["username"] == "testuser_e2e"
    print(f"  ✔ Public key endpoint OK: {pk_result['username']}")

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED ✔")
    print("=" * 60)

if __name__ == "__main__":
    test_all()
