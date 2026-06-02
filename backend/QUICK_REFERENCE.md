# Quick Reference: Manual Testing

**Location:** `c:\Users\Sarva\Desktop\demo2 - Copy (2)\backend`

---

## Setup (Run Once)

```bash
cd c:\Users\Sarva\Desktop\demo2\ -\ Copy\ \(2\)\backend
```

---

## 1️⃣ REGISTER & GET TOKEN

```bash
curl -X POST http://localhost:8000/api/register -H "Content-Type: application/json" -d "{\"username\": \"testuser\", \"password\": \"testpass123\", \"signature_algorithm\": \"RSA-SHA256\"}"
```

**Copy the `token` value and run:**
```bash
set TOKEN=<paste-token-here>
```

**Verify:**
```bash
echo %TOKEN%
```

---

## 2️⃣ PHASE 1: SIGN FIRST DOCUMENT (GENESIS)

```bash
curl -X POST http://localhost:8000/api/sign-document -H "Authorization: Token %TOKEN%" -F "data=Initial version - test document" -o signed_v1.json && type signed_v1.json
```

**Look for:**
- `"prev_chain_hash": "GENESIS"`
- `"version_no": "1"`
- `"chain_hash": "abc123..."`

**Save document ID:**
```bash
set DOC_ID=<copy-document_id-from-json>
```

---

## 3️⃣ PHASE 2A: ADD VERSION 2

```bash
curl -X POST http://localhost:8000/api/add-document-version -H "Authorization: Token %TOKEN%" -F "document_id=%DOC_ID%" -F "data=Updated version - more content" -o signed_v2.json && type signed_v2.json
```

**Look for:**
- `"prev_chain_hash"` matches V1's `"chain_hash"`
- `"version_no": "2"`

---

## 3️⃣ PHASE 2B: ADD VERSION 3

```bash
curl -X POST http://localhost:8000/api/add-document-version -H "Authorization: Token %TOKEN%" -F "document_id=%DOC_ID%" -F "data=Final version - completed" -o signed_v3.json && type signed_v3.json
```

**Look for:**
- `"prev_chain_hash"` matches V2's `"chain_hash"`
- `"version_no": "3"`

---

## 4️⃣ PHASE 3: VERIFY COMPLETE CHAIN

```bash
curl -X POST http://localhost:8000/api/verify-document -F "file=@signed_v3.json" -s | python -m json.tool
```

**Look for:**
```json
"chain_verification": {
  "status": "valid",
  "verified_versions": 3,
  "broken_at_version": null
}
```

✅ **SUCCESS!**

---

## 📊 DATABASE VERIFICATION

**Open a NEW terminal:**

```bash
cd c:\Users\Sarva\Desktop\demo2\ -\ Copy\ \(2\)\backend
python manage.py shell
```

**In the Python shell:**

```python
from api.models import DocumentRecord

record = DocumentRecord.objects.get(doc_id='<your-doc-id>')
versions = list(record.versions.order_by('version_no'))

for i, v in enumerate(versions, 1):
    print(f"\nV{i}:")
    print(f"  prev_chain_hash: {v.prev_chain_hash[:30]}...")
    print(f"  chain_hash:      {v.chain_hash[:30]}...")
    if i > 1:
        prev_v = versions[i-2]
        match = (prev_v.chain_hash == v.prev_chain_hash)
        print(f"  Link valid: {match} ✓" if match else f"  Link valid: {match} ✗")

exit()
```

**Expected:** All links should show `True ✓`

---

## 🎯 TEST TAMPERING (Optional)

```bash
python test_tampering.py
```

This automatically:
- Tampers with V1 payload → detects at V1 ✓
- Breaks V2 link → detects at V2 ✓
- Corrupts V2 signature → detects at V2 ✓
- Tampers with V3 payload → detects at V3 ✓
- Tests recovery ✓

---

## 📋 Checklist

- [ ] Backend running: `python manage.py runserver`
- [ ] Registered user & saved TOKEN
- [ ] Phase 1: Signed V1 with GENESIS anchor
- [ ] Phase 2: Added V2 & V3 with correct links
- [ ] Phase 3: Verified complete chain (status=valid, broken_at=null)
- [ ] Database verified (all links match)
- [ ] (Optional) Tampering tests passed

---

## 🆘 Troubleshooting

**"Page not found"?**
→ Remove trailing slash: `/api/register` NOT `/api/register/`

**"Authorization failed"?**
→ Make sure TOKEN is set: `echo %TOKEN%`

**"Document not found"?**
→ Make sure DOC_ID is correct: `echo %DOC_ID%`

**JSON parsing error?**
→ Install Python: `pip install python` or skip pretty-printing
