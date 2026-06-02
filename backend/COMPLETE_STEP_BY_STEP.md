# Complete Step-by-Step Testing Guide - Hash Chaining & Immutable Storage

## Prerequisites
- Backend running: `python manage.py runserver` (should be running on http://localhost:8000)
- curl installed (comes with Windows 10+)
- Optional: Python installed (for pretty-printing JSON)

---

## STEP 1: Create/Login to Test User Account

### Step 1A: Open a NEW terminal (keep backend running in the other one)

```bash
cd c:\Users\Sarva\Desktop\demo2\ -\ Copy\ \(2\)\backend
```

### Step 1B: Try to login first
```bash
curl -X POST http://localhost:8000/api/login/ \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"testuser\", \"password\": \"testpass123\"}"
```

**Look for response like:**
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "username": "testuser",
  "role": "user",
  "signature_algorithm": "RSA-SHA256"
}
```

**If you see this:** Go to Step 1D ✓

**If you see "Invalid username or password":** Go to Step 1C

### Step 1C: Register a new user (if login failed)
```bash
curl -X POST http://localhost:8000/api/register/ \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"testuser\", \"password\": \"testpass123\", \"signature_algorithm\": \"RSA-SHA256\"}"
```

**Expected response:**
```json
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "username": "testuser",
  "role": "user",
  "signature_algorithm": "RSA-SHA256"
}
```

### Step 1D: Save the TOKEN
Copy the token value from the response and save it as an environment variable:

```bash
set TOKEN=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

Replace `eyJ0eXAi...` with your actual token from the response.

**Verify it's saved:**
```bash
echo %TOKEN%
```

Should print your token.

---

## STEP 2: PHASE 1 - Create First Document (GENESIS Anchor)

### Step 2A: Sign a new document
```bash
curl -X POST http://localhost:8000/api/sign-document/ \
  -H "Authorization: Token %TOKEN%" \
  -F "data=Initial version - This is my test document" \
  -o signed_v1.json

type signed_v1.json
```

**You should see a JSON file with:**
- `"version_no": "1"`
- `"prev_chain_hash": "GENESIS"`
- `"chain_hash": "5a8c3d9e2f4b1a6c..."`
- `"signature": "..."`

### Step 2B: Save document ID and chain hash
Extract from the file and save:

```bash
set DOC_ID=abc123-def456-ghi789
set V1_CHAIN_HASH=5a8c3d9e2f4b1a6c7d8e9f0a1b2c3d4e
```

(Replace with actual values from signed_v1.json)

### Step 2C: Verify in database
Open a **NEW terminal** and run:

```bash
cd c:\Users\Sarva\Desktop\demo2\ -\ Copy\ \(2\)\backend
python manage.py shell
```

In the Python shell:
```python
from api.models import DocumentRecord, DocumentVersion

# Replace with your actual DOC_ID
record = DocumentRecord.objects.get(doc_id='abc123-def456-ghi789')
v1 = record.versions.first()

print("=== PHASE 1 VERIFICATION ===")
print(f"Version: {v1.version_no}")
print(f"prev_chain_hash: {v1.prev_chain_hash}")
print(f"chain_hash: {v1.chain_hash}")
print(f"algorithm: {v1.algorithm}")
```

**Expected output:**
```
=== PHASE 1 VERIFICATION ===
Version: 1
prev_chain_hash: GENESIS
chain_hash: 5a8c3d9e2f4b1a6c7d8e9f0a1b2c3d4e
algorithm: RSA-SHA256
```

**✅ Phase 1 Complete!** V1 created with GENESIS anchor.

---

## STEP 3: PHASE 2 - Add Version 2 & 3

### Step 3A: Add Version 2 (in curl terminal)
```bash
curl -X POST http://localhost:8000/api/add-document-version/ \
  -H "Authorization: Token %TOKEN%" \
  -F "document_id=%DOC_ID%" \
  -F "data=Updated version - Added more content" \
  -o signed_v2.json

type signed_v2.json
```

**You should see:**
- `"version_no": "2"`
- `"prev_chain_hash": "5a8c3d9e2f4b1a6c..."` (matches V1's chain_hash)
- `"chain_hash": "ghi789jkl012mno345..."` (different from prev)

**Save V2's chain hash:**
```bash
set V2_CHAIN_HASH=ghi789jkl012mno345pqr678stu123vw
```

### Step 3B: Add Version 3
```bash
curl -X POST http://localhost:8000/api/add-document-version/ \
  -H "Authorization: Token %TOKEN%" \
  -F "document_id=%DOC_ID%" \
  -F "data=Final version - Completed" \
  -o signed_v3.json

type signed_v3.json
```

**Save V3's chain hash:**
```bash
set V3_CHAIN_HASH=xyz999abc111def222ghi333jkl444mno
```

### Step 3C: Verify chain links in database
**In the Django shell (from Step 2C):**

```python
record = DocumentRecord.objects.get(doc_id='abc123-def456-ghi789')
versions = list(record.versions.order_by('version_no'))

print("\n=== PHASE 2 CHAIN VALIDATION ===")
print(f"\nV1 chain_hash: {versions[0].chain_hash}")
print(f"\nV2:")
print(f"  prev_chain_hash: {versions[1].prev_chain_hash}")
print(f"  chain_hash: {versions[1].chain_hash}")
print(f"  Link valid? {versions[0].chain_hash == versions[1].prev_chain_hash}")

print(f"\nV3:")
print(f"  prev_chain_hash: {versions[2].prev_chain_hash}")
print(f"  chain_hash: {versions[2].chain_hash}")
print(f"  Link valid? {versions[1].chain_hash == versions[2].prev_chain_hash}")
```

**Expected output:**
```
=== PHASE 2 CHAIN VALIDATION ===

V1 chain_hash: 5a8c3d9e2f4b1a6c7d8e9f0a1b2c3d4e

V2:
  prev_chain_hash: 5a8c3d9e2f4b1a6c7d8e9f0a1b2c3d4e
  chain_hash: ghi789jkl012mno345pqr678stu123vw
  Link valid? True

V3:
  prev_chain_hash: ghi789jkl012mno345pqr678stu123vw
  chain_hash: xyz999abc111def222ghi333jkl444mno
  Link valid? True
```

**✅ Phase 2 Complete!** All chain links are valid.

---

## STEP 4: PHASE 3 - Verify Valid Chain Integrity

### Step 4A: Verify the complete chain (in curl terminal)
```bash
curl -X POST http://localhost:8000/api/verify-document/ \
  -F "file=@signed_v3.json"
```

**Pretty print the response:**
```bash
curl -X POST http://localhost:8000/api/verify-document/ \
  -F "file=@signed_v3.json" | python -m json.tool
```

Or save it first:
```bash
curl -X POST http://localhost:8000/api/verify-document/ \
  -F "file=@signed_v3.json" -o verify_response.json

type verify_response.json
```

**You should see:**
```json
{
  "status": "valid",
  "message": "Document Integrity Verified",
  "chain_verification": {
    "status": "valid",
    "verified_versions": 3,
    "broken_at_version": null
  },
  "algorithm_used": "RSA-PKCS1v15",
  "verification_details": {
    "signature_status": "Verified / Authentic",
    "signed_by": "testuser",
    "timestamp": "2026-05-25T10:00:05..."
  }
}
```

**Key points to verify:**
- ✅ `"status": "valid"` - Signature is valid
- ✅ `"chain_verification.status": "valid"` - Chain is intact
- ✅ `"verified_versions": 3` - All 3 versions checked
- ✅ `"broken_at_version": null` - No tampering detected

**✅ Phase 3 Complete!** Entire chain verified successfully.

---

## STEP 5: ADVANCED - Tamper with Database & Detect

### Step 5A: Tamper with V1's payload (in Django shell)

```python
from api.models import DocumentVersion
from hashlib import sha256

record = DocumentRecord.objects.get(doc_id='abc123-def456-ghi789')
v1 = record.versions.get(version_no=1)

print(f"Original V1 payload_hash: {v1.payload_hash}")

# ATTACKER MODIFIES THE DATABASE!
v1.payload_hash = "tampered_hash_xyz999abc111def222"
v1.save()

print(f"TAMPERED V1 payload_hash: {v1.payload_hash}")
```

### Step 5B: Verify - Should detect tampering (in curl terminal)
```bash
curl -X POST http://localhost:8000/api/verify-document/ \
  -F "file=@signed_v3.json" | python -m json.tool | findstr /A:2 "chain_verification"
```

Or save and view:
```bash
curl -X POST http://localhost:8000/api/verify-document/ \
  -F "file=@signed_v3.json" > verify_tampered.json

type verify_tampered.json
```

**Look for:**
```json
"chain_verification": {
  "status": "invalid",
  "verified_versions": 3,
  "broken_at_version": 1
}
```

**🎯 SUCCESS!** Tampering detected at version 1!

### Step 5C: Understand why it broke (in Django shell)

```python
from api.views import _compute_chain_hash

v1 = record.versions.get(version_no=1)

# Recompute what V1's chain_hash SHOULD be
recomputed = _compute_chain_hash(
    prev_chain_hash="GENESIS",
    payload_hash=v1.payload_hash,  # ← Now tampered!
    algorithm=v1.algorithm,
    signature_b64=v1.signature_b64,
    timestamp_iso=v1.created_at.isoformat()
)

print(f"\nV1 stored chain_hash: {v1.chain_hash}")
print(f"V1 recomputed hash:   {recomputed}")
print(f"Match? {v1.chain_hash == recomputed}")
```

**Expected output:**
```
V1 stored chain_hash: 5a8c3d9e2f4b1a6c7d8e9f0a1b2c3d4e
V1 recomputed hash:   xxx999yyy111zzz222aaa333bbb444ccc
Match? False
```

✅ **This mismatch triggers the tamper detection!**

### Step 5D: Restore V1 (in Django shell)

```python
# Get the original artifact
artifact = v1.artifact
original_hash = sha256(bytes(artifact.original_bytes)).hexdigest()
v1.payload_hash = original_hash
v1.save()

print(f"✓ Restored V1 payload_hash: {v1.payload_hash}")
```

### Step 5E: Verify again - Should be valid (in curl terminal)

```bash
curl -X POST http://localhost:8000/api/verify-document/ \
  -F "file=@signed_v3.json" | python -m json.tool | findstr /A:2 "chain_verification"
```

**Should show:**
```json
"chain_verification": {
  "status": "valid",
  "verified_versions": 3,
  "broken_at_version": null
}
```

✅ **Chain is valid again after restoration!**

---

## STEP 6: ADVANCED - Tamper with V2's Link

### Step 6A: Break the link (in Django shell)

```python
v2 = record.versions.get(version_no=2)

print(f"Original V2 prev_chain_hash: {v2.prev_chain_hash}")

# ATTACKER BREAKS THE LINK!
v2.prev_chain_hash = "broken_link_xyz999abc111def222ghi"
v2.save()

print(f"BROKEN V2 prev_chain_hash: {v2.prev_chain_hash}")
```

### Step 6B: Verify - Should detect immediate link failure (in curl terminal)

```bash
curl -X POST http://localhost:8000/api/verify-document/ \
  -F "file=@signed_v3.json" | python -m json.tool | findstr /A:2 "chain_verification"
```

**Should show:**
```json
"chain_verification": {
  "status": "invalid",
  "verified_versions": 3,
  "broken_at_version": 2
}
```

✅ **Link failure detected at version 2!**

### Step 6C: Restore V2 link (in Django shell)

```python
# Restore the correct link
v1_chain = record.versions.get(version_no=1).chain_hash
v2.prev_chain_hash = v1_chain
v2.save()

print(f"✓ Restored V2 prev_chain_hash: {v2.prev_chain_hash}")
```

### Step 6D: Verify - Should be valid again (in curl terminal)

```bash
curl -X POST http://localhost:8000/api/verify-document/ \
  -F "file=@signed_v3.json" | python -m json.tool | findstr /A:2 "chain_verification"
```

**Should show:**
```json
"chain_verification": {
  "status": "valid",
  "verified_versions": 3,
  "broken_at_version": null
}
```

✅ **Chain recovered!**

---

## STEP 7: ADVANCED - Tamper with V2's Signature

### Step 7A: Corrupt the signature (in Django shell)

```python
v2 = record.versions.get(version_no=2)
original_sig = v2.signature_b64

print(f"Original V2 signature (first 20 chars): {original_sig[:20]}...")

# ATTACKER CORRUPTS THE SIGNATURE!
v2.signature_b64 = "corrupt_signature_data_xyz999abc111"
v2.save()

print(f"CORRUPTED V2 signature: {v2.signature_b64}")
```

### Step 7B: Verify - Should detect (in curl terminal)

```bash
curl -X POST http://localhost:8000/api/verify-document/ \
  -F "file=@signed_v3.json" | python -m json.tool | findstr /A:2 "chain_verification"
```

**Should show:**
```json
"chain_verification": {
  "status": "invalid",
  "verified_versions": 3,
  "broken_at_version": 2
}
```

✅ **Signature tampering detected at version 2!**

### Step 7C: Restore V2 signature (in Django shell)

```python
v2.signature_b64 = original_sig
v2.save()

print(f"✓ Restored V2 signature")
```

### Step 7D: Verify - Should be valid again (in curl terminal)

```bash
curl -X POST http://localhost:8000/api/verify-document/ \
  -F "file=@signed_v3.json" | python -m json.tool | findstr /A:2 "chain_verification"
```

**Should show:**
```json
"chain_verification": {
  "status": "valid",
  "verified_versions": 3,
  "broken_at_version": null
}
```

✅ **Chain valid again!**

---

## SUMMARY: Test Results Matrix

| Test | Expected Result | Status |
|------|---|---|
| **Baseline** | 3 versions, valid chain, broken_at_version=null | ✅ |
| **Tamper V1 payload** | Detected at version 1 | ✅ |
| **Restore V1** | Chain valid again | ✅ |
| **Break V2 link** | Detected at version 2 | ✅ |
| **Restore V2 link** | Chain valid again | ✅ |
| **Corrupt V2 sig** | Detected at version 2 | ✅ |
| **Restore V2 sig** | Chain valid again | ✅ |

---

## Clean Up

### Exit Django shell:
```python
exit()
```

### Stop backend server:
Press `CTRL+BREAK` in the backend terminal.

---

## ✅ SUCCESS!

If all tests passed, your hash chaining system is **working perfectly**! 

You've proven:
- ✅ Append-only storage (versions never overwritten)
- ✅ Hash chaining (each block links to previous)
- ✅ GENESIS anchor (first block properly anchored)
- ✅ Tamper detection (any modification detected)
- ✅ Precise localization (exact version identified)
- ✅ Recovery (chain valid after restoration)

🎉 **Your immutable storage system is secure!**
