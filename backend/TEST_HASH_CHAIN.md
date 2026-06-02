# Testing Hash Chaining & Immutable Storage

Complete test guide to validate Phase 1, 2, and 3 of the append-only versioning system.

---

## Test Setup

### 1. Start Backend
```bash
cd backend
python manage.py runserver
```

### 2. Register User (if needed)
```bash
curl -X POST http://localhost:8000/api/register/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "testpass123",
    "signature_algorithm": "RSA-SHA256"
  }'
```
Response will include `token`. Save it:
```
TOKEN="your_token_here"
```

---

## PHASE 1: Create First Document (GENESIS Anchor)

### Test 1.1: Sign a New Document
```bash
curl -X POST http://localhost:8000/api/sign-document/ \
  -H "Authorization: Token $TOKEN" \
  -F "data=Initial version - This is my document" \
  -o signed_v1.json

cat signed_v1.json | python -m json.tool
```

**Expected Response:**
```json
{
  "document_id": "some-uuid-1234",
  "version_no": "1",
  "prev_chain_hash": "GENESIS",
  "chain_hash": "abc123def456...",
  "hash": "payload_hash_here",
  "signature": "...",
  "signed_by": "testuser",
  "timestamp": "2026-05-25T10:00:00.000000+00:00"
}
```

**Save these values** for next tests:
```bash
DOC_ID="your_document_id_from_response"
V1_CHAIN_HASH="abc123def456..."
```

### Test 1.2: Verify Database State
```bash
# Connect to your database
python manage.py shell
```

In Django shell:
```python
from api.models import DocumentRecord, DocumentVersion
from django.contrib.auth import get_user_model

user = get_user_model().objects.get(username='testuser')
record = DocumentRecord.objects.get(doc_id='your_document_id')

print(f"Record Owner: {record.owner.username}")
print(f"Created At: {record.created_at}")

version = record.versions.first()
print(f"\nVersion {version.version_no}:")
print(f"  prev_chain_hash: {version.prev_chain_hash}")
print(f"  chain_hash: {version.chain_hash}")
print(f"  payload_hash: {version.payload_hash}")
print(f"  algorithm: {version.algorithm}")
```

**Expected Output:**
```
Record Owner: testuser
Created At: 2026-05-25 10:00:00+00:00

Version 1:
  prev_chain_hash: GENESIS
  chain_hash: abc123def456...
  payload_hash: def456ghi789...
  algorithm: RSA-SHA256
```

---

## PHASE 2: Append New Versions

### Test 2.1: Add Version 2 (via add-document-version endpoint)
```bash
curl -X POST http://localhost:8000/api/add-document-version/ \
  -H "Authorization: Token $TOKEN" \
  -F "document_id=$DOC_ID" \
  -F "data=Updated version - Added more content" \
  -o signed_v2.json

cat signed_v2.json | python -m json.tool
```

**Expected Response:**
```json
{
  "document_id": "same_as_v1",
  "version_no": "2",
  "prev_chain_hash": "abc123def456...",  // ← MUST match v1's chain_hash
  "chain_hash": "ghi789jkl012...",
  "hash": "new_payload_hash",
  "signed_by": "testuser"
}
```

**Save:**
```bash
V2_CHAIN_HASH="ghi789jkl012..."
```

### Test 2.2: Verify Chain Link in Database
```python
# In Django shell
record = DocumentRecord.objects.get(doc_id='$DOC_ID')
versions = list(record.versions.order_by('version_no'))

v1 = versions[0]
v2 = versions[1]

print(f"V1 chain_hash:  {v1.chain_hash}")
print(f"V2 prev_hash:   {v2.prev_chain_hash}")
print(f"Match: {v1.chain_hash == v2.prev_chain_hash}")
```

**Expected Output:**
```
V1 chain_hash:  abc123def456...
V2 prev_hash:   abc123def456...
Match: True
```

### Test 2.3: Add Version 3
```bash
curl -X POST http://localhost:8000/api/add-document-version/ \
  -H "Authorization: Token $TOKEN" \
  -F "document_id=$DOC_ID" \
  -F "data=Final version - Completed" \
  -o signed_v3.json

cat signed_v3.json | python -m json.tool
```

**Expected:**
- version_no: 3
- prev_chain_hash: matches V2's chain_hash
- Save V3's chain_hash

### Test 2.4: Verify Full Chain in Database
```python
# In Django shell
record = DocumentRecord.objects.get(doc_id='$DOC_ID')
versions = list(record.versions.order_by('version_no'))

for i, v in enumerate(versions, 1):
    print(f"\nVersion {i}:")
    print(f"  version_no: {v.version_no}")
    print(f"  prev_chain_hash: {v.prev_chain_hash}")
    print(f"  chain_hash: {v.chain_hash}")
    print(f"  payload_hash: {v.payload_hash}")

# Check links
print("\n--- CHAIN VALIDATION ---")
for i in range(1, len(versions)):
    prev_v = versions[i-1]
    curr_v = versions[i]
    match = prev_v.chain_hash == curr_v.prev_chain_hash
    print(f"V{i} → V{i+1}: {match} ✓" if match else f"V{i} → V{i+1}: BROKEN ✗")
```

**Expected Output:**
```
Version 1:
  version_no: 1
  prev_chain_hash: GENESIS
  chain_hash: abc123...
  payload_hash: def456...

Version 2:
  version_no: 2
  prev_chain_hash: abc123...
  chain_hash: ghi789...
  payload_hash: jkl012...

Version 3:
  version_no: 3
  prev_chain_hash: ghi789...
  chain_hash: mno345...
  payload_hash: pqr678...

--- CHAIN VALIDATION ---
V1 → V2: True ✓
V2 → V3: True ✓
```

---

## PHASE 3: Verify Chain Integrity

### Test 3.1: Verify Valid Chain (Signature Valid)
```bash
curl -X POST http://localhost:8000/api/verify-document/ \
  -F "file=@signed_v3.json" \
  | python -m json.tool
```

**Expected Response:**
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
    "timestamp": "2026-05-25T10:00:05.000000+00:00"
  }
}
```

---

## PHASE 3 ADVANCED: Detect Database Tampering

### Test 3.2: Simulate Attacker Modifying V1 in Database

**Attacker Scenario**: Someone broke into the database and changed V1's payload.

#### Step 1: Get V1's Artifact
```python
# In Django shell
from api.models import DocumentVersion
import base64

record = DocumentRecord.objects.get(doc_id='$DOC_ID')
v1 = record.versions.get(version_no=1)
artifact = v1.artifact

print(f"Original payload: {artifact.original_bytes}")
print(f"Original hash: {v1.payload_hash}")
print(f"V1 chain_hash: {v1.chain_hash}")
```

#### Step 2: Modify V1's Payload Hash (Simulate Tampering)
```python
# Attacker modifies the database record
v1.payload_hash = "tampered_hash_xyz999..."  # ← Simulate modification
v1.save()

print(f"Modified V1 payload_hash to: {v1.payload_hash}")
```

#### Step 3: Run Verification - Should Detect Tampering
```bash
curl -X POST http://localhost:8000/api/verify-document/ \
  -F "file=@signed_v3.json" \
  | python -m json.tool
```

**Expected Response:**
```json
{
  "status": "valid",
  "message": "Document Integrity Verified",
  "chain_verification": {
    "status": "invalid",
    "verified_versions": 3,
    "broken_at_version": 1
  }
}
```

**Key Observation**: 
- Signature still valid (V3 data unchanged)
- But chain verification detects the tampering at V1
- broken_at_version: 1 points to where the problem is

#### Step 4: Verify Why It Breaks
```python
# In Django shell
from api.views import _compute_chain_hash

v1 = record.versions.get(version_no=1)

# Recompute what V1's chain_hash SHOULD be
expected_chain = _compute_chain_hash(
    prev_chain_hash="GENESIS",
    payload_hash=v1.payload_hash,  # ← Now tampered!
    algorithm=v1.algorithm,
    signature_b64=v1.signature_b64,
    timestamp_iso=v1.created_at.isoformat()
)

print(f"V1's stored chain_hash: {v1.chain_hash}")
print(f"Recomputed with tampered payload: {expected_chain}")
print(f"Match: {expected_chain == v1.chain_hash}")
```

**Expected Output:**
```
V1's stored chain_hash: abc123def456...
Recomputed with tampered payload: xxx111yyy222...
Match: False
```

**This is where detection happens!** The recomputed hash doesn't match, so verification fails.

### Test 3.3: Fix and Verify Recovery

Restore V1's original payload hash:
```python
# Get the artifact and restore
artifact = v1.artifact
correct_hash = sha256(bytes(artifact.original_bytes)).hexdigest()
v1.payload_hash = correct_hash
v1.save()

print(f"Restored V1 payload_hash to: {v1.payload_hash}")
```

Re-run verification:
```bash
curl -X POST http://localhost:8000/api/verify-document/ \
  -F "file=@signed_v3.json" \
  | python -m json.tool
```

**Expected Response:**
```json
{
  "status": "valid",
  "message": "Document Integrity Verified",
  "chain_verification": {
    "status": "valid",
    "verified_versions": 3,
    "broken_at_version": null
  }
}
```

---

## Test 3.4: Tamper with Middle Version (V2)

#### Step 1: Modify V2's Signature
```python
# In Django shell
v2 = record.versions.get(version_no=2)
original_sig = v2.signature_b64

# Tamper
v2.signature_b64 = "tampered_signature_corrupt_data"
v2.save()

print(f"Modified V2 signature")
```

#### Step 2: Run Verification
```bash
curl -X POST http://localhost:8000/api/verify-document/ \
  -F "file=@signed_v3.json" \
  | python -m json.tool
```

**Expected Response:**
```json
{
  "status": "valid",
  "message": "Document Integrity Verified",
  "chain_verification": {
    "status": "invalid",
    "verified_versions": 3,
    "broken_at_version": 2
  }
}
```

**Why V2 breaks**: When recomputing V2's chain_hash with the tampered signature_b64, it produces a different result. V3's prev_chain_hash won't match V2's now-invalid chain_hash.

#### Step 3: Restore
```python
v2.signature_b64 = original_sig
v2.save()
```

---

## Test 3.5: Tamper with prev_chain_hash (Link)

#### Step 1: Break the Link
```python
# In Django shell
v2 = record.versions.get(version_no=2)
v2.prev_chain_hash = "broken_link_xxx999..."
v2.save()

print(f"Modified V2 prev_chain_hash")
```

#### Step 2: Run Verification
```bash
curl -X POST http://localhost:8000/api/verify-document/ \
  -F "file=@signed_v3.json" \
  | python -m json.tool
```

**Expected Response:**
```json
{
  "status": "valid",
  "chain_verification": {
    "status": "invalid",
    "verified_versions": 3,
    "broken_at_version": 2
  }
}
```

**Why it breaks**: V2's prev_chain_hash no longer matches V1's chain_hash, breaking the link immediately.

---

## Comprehensive Test Matrix

| Test | Action | Expected Detection | broken_at_version |
|------|--------|-------------------|------------------|
| Valid Chain | All 3 versions correct | ✓ valid | null |
| Tamper V1 payload | Modify v1.payload_hash | ✓ invalid | 1 |
| Tamper V1 signature | Modify v1.signature_b64 | ✓ invalid | 1 |
| Tamper V2 signature | Modify v2.signature_b64 | ✓ invalid | 2 |
| Break V2→V3 link | Modify v2.prev_chain_hash | ✓ invalid | 2 |
| Break V1→V2 link | Modify v1.chain_hash | ✓ invalid | 2 |
| Add fake V4 after v3 | Insert new row with wrong prev | ✓ invalid | 4 |

---

## Quick Test Script

Save as `test_chain.sh`:

```bash
#!/bin/bash

TOKEN="your_token"
DOC_ID="your_doc_id"

echo "=== TEST 1: Sign New Document ==="
curl -X POST http://localhost:8000/api/sign-document/ \
  -H "Authorization: Token $TOKEN" \
  -F "data=Test document" | python -m json.tool | head -20

echo -e "\n=== TEST 2: Add Version ==="
curl -X POST http://localhost:8000/api/add-document-version/ \
  -H "Authorization: Token $TOKEN" \
  -F "document_id=$DOC_ID" \
  -F "data=Updated content" | python -m json.tool | head -20

echo -e "\n=== TEST 3: Verify ==="
# Use the latest signed_document.json
curl -X POST http://localhost:8000/api/verify-document/ \
  -F "file=@signed.json" | python -m json.tool | grep -A 10 "chain_verification"
```

Run:
```bash
chmod +x test_chain.sh
./test_chain.sh
```

---

## SQL Queries to Inspect Database

```sql
-- View all documents for a user
SELECT dr.doc_id, dr.owner_id, COUNT(*) as version_count
FROM api_documentrecord dr
LEFT JOIN api_documentversion dv ON dv.record_id = dr.id
GROUP BY dr.id
ORDER BY dr.created_at DESC;

-- View all versions of a document
SELECT version_no, prev_chain_hash, chain_hash, payload_hash, algorithm, created_at
FROM api_documentversion
WHERE record_id = (SELECT id FROM api_documentrecord WHERE doc_id = 'your_doc_id')
ORDER BY version_no;

-- Check if chain is valid (manually)
SELECT 
  version_no,
  prev_chain_hash,
  chain_hash,
  payload_hash,
  CASE 
    WHEN version_no = 1 AND prev_chain_hash = 'GENESIS' THEN 'VALID_ANCHOR'
    WHEN version_no > 1 THEN 'VALIDATE_LINK'
    ELSE 'ERROR'
  END as status
FROM api_documentversion
WHERE record_id = (SELECT id FROM api_documentrecord WHERE doc_id = 'your_doc_id')
ORDER BY version_no;
```

---

## Summary: What Should Happen

| Scenario | Result |
|----------|--------|
| **Sign new doc** | v1 created with prev_chain_hash = "GENESIS" |
| **Add version** | v2 created with prev_chain_hash = v1.chain_hash |
| **Verify valid chain** | status="valid", broken_at_version=null |
| **Tamper any block** | status="invalid", broken_at_version=N |
| **Break any link** | status="invalid", broken_at_version=N |
| **Restore original** | status="valid" again |

✅ If all tests pass, your hash chaining is working correctly!
