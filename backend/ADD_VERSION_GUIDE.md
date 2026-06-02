# How to Add Version 2 & 3

You can add versions using **browser** OR **curl**. Here's both:

---

## 🌐 Method 1: Browser (Frontend)

### Prerequisites
✅ Backend running on `http://localhost:8000`  
✅ Frontend running on `http://localhost:4200`  
✅ You're logged in  
✅ You've already created V1 (GENESIS anchor)

---

### Step 1: Go to "Add Version" Page

In browser, navigate to:
```
http://localhost:4200
```

Click on **"Add Version"** in the navigation menu.

---

### Step 2: Select Document ID

You should see a dropdown with existing document IDs.

**Choose the document you created in Phase 1** (the one with GENESIS anchor).

Or manually paste the document ID in the text field below.

---

### Step 3: Upload or Type Content for V2

**Option A: Upload a file**
- Drag & drop a text file into the upload zone
- Or click to browse and select a file

**Option B: Type text directly**
```
Updated version - Added more content
```

---

### Step 4: Click "Add Version"

Button will be at the bottom of the form.

**Wait for response** - You'll see:
```json
{
  "version_no": "2",
  "prev_chain_hash": "18123c76e399e4bf1fc08c463054150a87d4cd13...",
  "chain_hash": "ghi789jkl012mno345pqr678stu123vw...",
  "document_id": "bcab8c2a-e48a-4655-9a04-38aafd4787ac"
}
```

✅ **V2 Created!** Notice `prev_chain_hash` matches V1's `chain_hash`

---

### Step 5: Add V3 (Same Process)

Go back to the **Add Version** page.

Select the **same document ID**.

Upload/type new content:
```
Final version - Completed
```

Click **"Add Version"** again.

**V3 should be created** with:
- `version_no: "3"`
- `prev_chain_hash` matching V2's `chain_hash`

---

### Step 6: View Results in Browser

Go to **"Logs"** page to see all versions created.

---

## 💻 Method 2: Curl Commands (Terminal)

### Prerequisites (from Quick Reference)

```bash
set TOKEN=d11950022ec4ef7d3628114a422b3a...
set DOC_ID=bcab8c2a-e48a-4655-9a04-38aafd4787ac
```

---

### Add Version 2

**In Terminal 2:**

```bash
curl -X POST http://localhost:8000/api/add-document-version -H "Authorization: Token %TOKEN%" -F "document_id=%DOC_ID%" -F "data=Updated version - Added more content" -o signed_v2.json && type signed_v2.json
```

**Expected response:**
```json
{
  "version_no": "2",
  "prev_chain_hash": "18123c76e399e4bf1fc08c463054150a87d4cd13...",
  "chain_hash": "ghi789jkl012mno345pqr678stu123vw...",
  "document_id": "bcab8c2a-e48a-4655-9a04-38aafd4787ac"
}
```

✅ Check: `prev_chain_hash` should match V1's `chain_hash`

---

### Add Version 3

**In Terminal 2:**

```bash
curl -X POST http://localhost:8000/api/add-document-version -H "Authorization: Token %TOKEN%" -F "document_id=%DOC_ID%" -F "data=Final version - Completed" -o signed_v3.json && type signed_v3.json
```

**Expected response:**
```json
{
  "version_no": "3",
  "prev_chain_hash": "ghi789jkl012mno345pqr678stu123vw...",
  "chain_hash": "xyz999abc111def222ghi333jkl444mno...",
  "document_id": "bcab8c2a-e48a-4655-9a04-38aafd4787ac"
}
```

✅ Check: `prev_chain_hash` should match V2's `chain_hash`

---

## 📊 Verify Chain Links

### Via Database (Terminal 3)

```bash
python manage.py shell
```

```python
from api.models import DocumentRecord

record = DocumentRecord.objects.get(doc_id='bcab8c2a-e48a-4655-9a04-38aafd4787ac')
versions = list(record.versions.order_by('version_no'))

for i, v in enumerate(versions, 1):
    print(f"\nV{i}:")
    print(f"  prev_chain_hash: {v.prev_chain_hash[:30]}...")
    print(f"  chain_hash:      {v.chain_hash[:30]}...")
    if i > 1:
        prev_v = versions[i-2]
        match = (prev_v.chain_hash == v.prev_chain_hash)
        print(f"  Link valid: {'✓' if match else '✗'}")
```

**Expected:**
```
V1:
  prev_chain_hash: GENESIS
  chain_hash:      18123c76e399e4bf1fc08c463...

V2:
  prev_chain_hash: 18123c76e399e4bf1fc08c463...
  chain_hash:      ghi789jkl012mno345pqr678...
  Link valid: ✓

V3:
  prev_chain_hash: ghi789jkl012mno345pqr678...
  chain_hash:      xyz999abc111def222ghi333...
  Link valid: ✓
```

---

## ✅ Checklist

- [ ] V2 created with correct `prev_chain_hash` (matches V1's `chain_hash`)
- [ ] V3 created with correct `prev_chain_hash` (matches V2's `chain_hash`)
- [ ] Database shows all 3 versions linked correctly
- [ ] All links verified with `✓`

---

## 🎯 Next Steps

Once V2 and V3 are created, go to [QUICK_REFERENCE.md](QUICK_REFERENCE.md) **Step 4** to verify the complete chain!
