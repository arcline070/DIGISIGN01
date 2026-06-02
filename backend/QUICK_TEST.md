# Quick Start: Testing Hash Chaining

## 🚀 Run Automated Tests (Recommended)

### Step 1: Start Backend
```bash
cd backend
python manage.py runserver
```

### Step 2: Run Test Suite
In a new terminal:
```bash
cd backend
python test_hash_chain.py
```

**Expected Output:**
```
============================================================
HASH CHAINING & IMMUTABLE STORAGE TEST SUITE
============================================================

✓ PASS: User logged in: testuser
✓ PASS: Token acquired: eyJ0eXAiOiJKV1...

============================================================
PHASE 1: Create First Document - Sign New Document
============================================================

✓ PASS: document_id exists
✓ PASS: version_no is 1
✓ PASS: prev_chain_hash is GENESIS
✓ PASS: chain_hash exists
✓ PASS: signature exists
✓ PASS: hash exists
ℹ INFO: Document ID: abc123-def456-ghi789
ℹ INFO: Version: 1
ℹ INFO: Chain Hash: 5a8c3d9e2f4b...

[... Phase 2 and Phase 3 tests ...]

============================================================
TEST SUMMARY
============================================================

Tests Passed: 15/15

  register: PASS
  phase1_sign: PASS
  phase2_v2: PASS
  phase2_v3: PASS
  phase3_verify: PASS

✓ All tests passed!
```

---

## 🔍 Manual Verification (Step-by-Step)

### Option A: Using Django Shell (Best for Understanding)

#### Step 1: Create Document
```bash
cd backend
python manage.py shell
```

```python
# Register/login (if needed)
from django.contrib.auth import get_user_model
User = get_user_model()
user = User.objects.get(username='testuser')

# Create a document via API
from api.models import DocumentRecord, DocumentVersion
from django.utils import timezone

# Let the API create it via the browser or curl first
# Then we can inspect it
```

#### Step 2: Inspect the Database
```python
from api.models import DocumentRecord, DocumentVersion

# Get your document
record = DocumentRecord.objects.get(doc_id='your_doc_id_here')

# View all versions
for version in record.versions.order_by('version_no'):
    print(f"\nVersion {version.version_no}:")
    print(f"  prev_chain_hash: {version.prev_chain_hash}")
    print(f"  chain_hash: {version.chain_hash}")
    print(f"  payload_hash: {version.payload_hash}")
    print(f"  algorithm: {version.algorithm}")
    print(f"  created_at: {version.created_at}")
```

**Expected Output:**
```
Version 1:
  prev_chain_hash: GENESIS
  chain_hash: 5a8c3d9e2f4b1a6c7d8e9f0a1b2c3d4e
  payload_hash: def456ghi789jkl012mno345pqr678st
  algorithm: RSA-SHA256
  created_at: 2026-05-25 10:00:00+00:00

Version 2:
  prev_chain_hash: 5a8c3d9e2f4b1a6c7d8e9f0a1b2c3d4e
  chain_hash: xyz999abc111def222ghi333jkl444mno
  payload_hash: new_hash_value_here
  algorithm: RSA-SHA256
  created_at: 2026-05-25 10:01:00+00:00
```

#### Step 3: Validate Chain Manually
```python
# Check if chain is valid
versions = list(record.versions.order_by('version_no'))

print("\n✓ CHAIN VALIDATION:")
prev_version = None
for version in versions:
    if prev_version is None:
        # First version
        is_valid = version.prev_chain_hash == "GENESIS"
        print(f"Version {version.version_no}: prev_chain_hash == GENESIS? {is_valid}")
    else:
        # Link to previous
        is_valid = version.prev_chain_hash == prev_version.chain_hash
        print(f"Version {version.version_no}: links to v{prev_version.version_no}? {is_valid}")
    
    prev_version = version
```

**Expected Output:**
```
✓ CHAIN VALIDATION:
Version 1: prev_chain_hash == GENESIS? True
Version 2: links to v1? True
Version 3: links to v2? True
```

---

## 💥 Test Tampering Detection

### Step 1: Tamper with Database
```python
# In Django shell, continue from above

from hashlib import sha256

v1 = record.versions.get(version_no=1)

print(f"\nOriginal V1 payload_hash: {v1.payload_hash}")

# Attacker modifies the database!
v1.payload_hash = "tampered_hash_xyz999abc111def222"
v1.save()

print(f"Tampered V1 payload_hash: {v1.payload_hash}")
```

### Step 2: Verify - Should Detect Tampering
```bash
# Use the signed_v3.json file we created
curl -X POST http://localhost:8000/api/verify-document/ \
  -F "file=@signed_v3.json" | python -m json.tool
```

**Expected Response:**
```json
{
  "status": "valid",
  "chain_verification": {
    "status": "invalid",
    "verified_versions": 3,
    "broken_at_version": 1
  }
}
```

### Step 3: Understand Why It Broke
```python
# Back in Django shell
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

**Expected Output:**
```
V1 stored chain_hash: 5a8c3d9e2f4b1a6c7d8e9f0a1b2c3d4e
V1 recomputed hash:   xxx999yyy111zzz222aaa333bbb444ccc
Match? False
```

### Step 4: Fix & Verify Recovery
```python
# Restore original
from api.models import SignedDocumentArtifact

artifact = v1.artifact
original_hash = sha256(bytes(artifact.original_bytes)).hexdigest()
v1.payload_hash = original_hash
v1.save()

print(f"Restored V1 payload_hash: {v1.payload_hash}")
```

Re-run verification:
```bash
curl -X POST http://localhost:8000/api/verify-document/ \
  -F "file=@signed_v3.json" | python -m json.tool | grep -A 5 "chain_verification"
```

**Expected:**
```json
"chain_verification": {
  "status": "valid",
  "verified_versions": 3,
  "broken_at_version": null
}
```

---

## Test Different Tamper Scenarios

### Tamper With V2's Signature
```python
v2 = record.versions.get(version_no=2)
original_sig = v2.signature_b64

# Tamper
v2.signature_b64 = "corrupt_data_xyz123"
v2.save()
```

Verify → Should detect tampering at version 2

### Tamper With V2's Link (prev_chain_hash)
```python
v2 = record.versions.get(version_no=2)

# Break the link
v2.prev_chain_hash = "broken_link_xyz999"
v2.save()
```

Verify → Should detect tampering at version 2 (immediate link failure)

### Restore
```python
v2.prev_chain_hash = versions[0].chain_hash  # Restore correct link
v2.save()
```

---

## Checklist: What Should Work

- [ ] **Phase 1**: Sign creates V1 with prev_chain_hash="GENESIS"
- [ ] **Phase 2**: Add versions creates V2, V3 with correct chain links
- [ ] **Phase 3**: Verify shows status="valid" for valid chain
- [ ] **Tamper V1 payload**: Verify detects broken_at_version=1
- [ ] **Tamper V2 signature**: Verify detects broken_at_version=2
- [ ] **Break V2 link**: Verify detects broken_at_version=2 (immediate link failure)
- [ ] **Restore**: Verify shows status="valid" again
- [ ] **All 3 versions verified**: verified_versions=3

✅ If all pass, your hash chaining system is working perfectly!

---

## Troubleshooting

### "broken_at_version is null but status is invalid"
→ Something is wrong with the chain verification logic

### "Verify passes but database has tampered data"
→ Chain verification wasn't called in verify endpoint

### "broken_at_version is wrong (e.g., 2 when we tampered V1)"
→ Check the sequential validation loop - it might be skipping versions

### Need Help?
1. Check [TEST_HASH_CHAIN.md](TEST_HASH_CHAIN.md) for detailed explanations
2. Review the implementation in `backend/api/views.py`:
   - `_compute_chain_hash()` - how hashes are computed
   - `_build_chain_verification()` - how validation works
   - `_upsert_document_chain()` - how versions are created
