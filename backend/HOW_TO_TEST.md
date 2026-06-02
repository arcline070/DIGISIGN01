# Testing Hash Chaining & Immutable Storage - Complete Guide

## Overview

Your system implements a **3-phase append-only versioning architecture** with cryptographic hash chaining. This guide shows you how to test all three phases and detect database tampering.

---

## 🎯 Test Files Available

| File | Purpose | Difficulty | Time |
|------|---------|-----------|------|
| **test_quick.sh** | Automated bash script (curl-based) | ⭐ Easy | 1 min |
| **test_hash_chain.py** | Automated Python test suite | ⭐⭐ Medium | 2 min |
| **QUICK_TEST.md** | Step-by-step manual testing | ⭐⭐ Medium | 5 min |
| **TEST_HASH_CHAIN.md** | Complete manual guide with tampering tests | ⭐⭐⭐ Advanced | 15 min |

---

## 🚀 Fastest Test (1 minute)

### Method 1: Run Bash Script
```bash
cd backend
bash test_quick.sh
```

**What it does:**
1. Logs in as testuser
2. Signs a new document (Phase 1)
3. Adds 2 more versions (Phase 2)
4. Verifies the complete chain (Phase 3)

**Expected output:**
```
✓ Document signed
✓ Chain link valid: V1 → V2 ✓
✓ Chain link valid: V2 → V3 ✓
✓ Verification complete

✓ ALL TESTS PASSED
```

---

## 🧪 Automated Python Testing (2 minutes)

### Method 2: Run Python Test Suite
```bash
cd backend
python test_hash_chain.py
```

**What it does:**
- Comprehensive validation of all 3 phases
- Colored output for easy reading
- Saves signed documents for inspection
- Reports all test results

**Expected output:**
```
============================================================
HASH CHAINING & IMMUTABLE STORAGE TEST SUITE
============================================================

✓ PASS: User logged in: testuser
✓ PASS: document_id exists
✓ PASS: version_no is 1
✓ PASS: prev_chain_hash is GENESIS
[... more test results ...]

Tests Passed: 15/15

✓ All tests passed!
```

---

## 📋 Manual Testing (5-15 minutes)

### Method 3: Step-by-Step Instructions

See [QUICK_TEST.md](QUICK_TEST.md) for step-by-step manual testing:
- Register/login
- Sign documents via curl
- Inspect database with Django shell
- Validate chain manually
- Test tampering detection

### Method 4: Complete Testing Guide

See [TEST_HASH_CHAIN.md](TEST_HASH_CHAIN.md) for the most comprehensive guide:
- All curl commands
- Django shell inspection
- Database tampering scenarios
- Detailed expected outputs

---

## 🔥 What Gets Tested

### Phase 1: Create First Document
```
✓ New document gets version_no = 1
✓ First version gets prev_chain_hash = "GENESIS"
✓ chain_hash is computed correctly
✓ Signature is generated
✓ Document stored in database
```

### Phase 2: Append Versions
```
✓ New version increments version_no
✓ prev_chain_hash links to previous version's chain_hash
✓ Each new block creates a valid link
✓ All versions stored immutably (append-only)
```

### Phase 3: Verify Integrity
```
✓ Valid chain verification passes
✓ Chain verification included in response
✓ All versions checked in order
✓ Links validated correctly
```

---

## 💣 Testing Tampering Detection

After running the basic tests, try simulating an attacker:

### Via Django Shell
```bash
python manage.py shell
```

```python
from api.models import DocumentRecord

record = DocumentRecord.objects.get(doc_id='your_doc_id')
v1 = record.versions.get(version_no=1)

# Attacker modifies V1's payload
v1.payload_hash = "tampered_xyz999..."
v1.save()
```

### Then verify - Should show tampering:
```bash
curl -X POST http://localhost:8000/api/verify-document/ \
  -F "file=@signed_v3.json" | python -m json.tool
```

**Expected:**
```json
{
  "chain_verification": {
    "status": "invalid",
    "verified_versions": 3,
    "broken_at_version": 1
  }
}
```

✅ Tampering detected at version 1!

---

## 🎯 Test Matrix

The system should correctly handle all these scenarios:

| Scenario | Expected Outcome |
|----------|------------------|
| Valid chain with 3 versions | ✓ status=valid, broken_at_version=null |
| Tamper V1 payload | ✓ status=invalid, broken_at_version=1 |
| Tamper V2 signature | ✓ status=invalid, broken_at_version=2 |
| Break V1→V2 link | ✓ status=invalid, broken_at_version=2 |
| Break V2→V3 link | ✓ status=invalid, broken_at_version=3 |
| After restoration | ✓ status=valid, broken_at_version=null |

---

## ✅ Validation Checklist

After running tests, verify these requirements:

### Phase 1
- [ ] First version has `prev_chain_hash = "GENESIS"`
- [ ] `chain_hash` is computed correctly
- [ ] Signature is valid
- [ ] Document record created

### Phase 2
- [ ] Version 2's `prev_chain_hash` equals Version 1's `chain_hash`
- [ ] Version 3's `prev_chain_hash` equals Version 2's `chain_hash`
- [ ] Each version has unique `chain_hash`
- [ ] All versions stored (no overwrites)

### Phase 3 - Valid Chain
- [ ] `chain_verification.status = "valid"`
- [ ] `chain_verification.verified_versions = 3`
- [ ] `chain_verification.broken_at_version = null`

### Phase 3 - Tampering Detection
- [ ] Tampering detected in database
- [ ] `chain_verification.status = "invalid"`
- [ ] `broken_at_version` points to correct version
- [ ] Can be restored and reverified

---

## 🔧 Implementation Details (For Understanding)

### Hash Chaining Formula
```
chain_hash = SHA-256(
    prev_chain_hash | 
    payload_hash | 
    algorithm | 
    signature_b64 | 
    timestamp_iso
)
```

### Chain Structure
```
Version 1:
├─ prev_chain_hash: GENESIS
├─ chain_hash: abc123... (computed)
└─ payload_hash: def456...

Version 2:
├─ prev_chain_hash: abc123... (← links to V1)
├─ chain_hash: ghi789... (computed)
└─ payload_hash: jkl012...

Version 3:
├─ prev_chain_hash: ghi789... (← links to V2)
├─ chain_hash: mno345... (computed)
└─ payload_hash: pqr678...
```

### Verification Algorithm
```python
for each version in order:
    if version_no == 1:
        expected_prev = "GENESIS"
    else:
        expected_prev = previous_version.chain_hash
    
    if version.prev_chain_hash != expected_prev:
        report("TAMPERED", broken_at_version)
        return
    
    recomputed_chain = compute_chain_hash(
        version.prev_chain_hash,
        version.payload_hash,
        version.algorithm,
        version.signature_b64,
        version.created_at
    )
    
    if recomputed_chain != version.chain_hash:
        report("TAMPERED", broken_at_version)
        return

report("VALID", no break detected)
```

---

## 📊 Expected Test Results

### Successful Run
```
Phase 1: ✓ Document created with GENESIS anchor
Phase 2: ✓ Versions 2 & 3 added with valid links
Phase 3: ✓ Chain verification passed (3/3 versions valid)

Tampering Test: ✓ Tampering detected at correct version
Recovery Test:  ✓ Chain valid again after restoration
```

### What This Proves
- ✅ Append-only storage working (no overwrites)
- ✅ Hash chaining working (links valid)
- ✅ Chain verification working (detects tampering)
- ✅ Immutability enforced
- ✅ Tamper detection accurate

---

## 🚨 Troubleshooting

### Test fails with "Invalid signature"
→ Backend server might not be running
→ Check: `curl http://localhost:8000/api/login/`

### Test shows `broken_at_version` but chain should be valid
→ Check that Phase 1 created V1 with `prev_chain_hash = "GENESIS"` (not empty string)
→ Database might have stale data from previous test runs

### Tampering test doesn't detect modification
→ Verify that `_build_chain_verification()` is being called in `verify_document()`
→ Check that database modification actually took effect: requery the record

### Files not created (signed_v1.json, etc.)
→ Tests might have failed before file creation
→ Check API responses in curl output
→ Review full test output

---

## 📖 Next Steps

1. **Run** `bash test_quick.sh` (takes 1 minute)
2. **Verify** all tests pass
3. **Inspect** the generated JSON files (`signed_v1.json`, etc.)
4. **Test** tampering detection using Django shell
5. **Review** the implementation in `backend/api/views.py`

---

## 📚 Related Files

- **Implementation**: `backend/api/views.py`
  - `_compute_chain_hash()` - Hash computation
  - `_upsert_document_chain()` - Phase 1 & 2 logic
  - `_build_chain_verification()` - Phase 3 logic
  - `verify_document()` - Verification endpoint

- **Models**: `backend/api/models.py`
  - `DocumentRecord` - Logical document stream
  - `DocumentVersion` - Immutable version blocks

- **Documentation**: 
  - `TEST_HASH_CHAIN.md` - Comprehensive manual guide
  - `QUICK_TEST.md` - Step-by-step instructions

---

## ✨ Success Criteria

Your hash chaining is **working correctly** when:

1. ✅ Phase 1 creates V1 with `prev_chain_hash = "GENESIS"`
2. ✅ Phase 2 creates V2/V3 with valid chain links
3. ✅ Phase 3 verifies valid chains correctly
4. ✅ Tampering detection identifies exact version
5. ✅ Chain is valid again after restoration

🎉 **All tests passing = System is secure!**
