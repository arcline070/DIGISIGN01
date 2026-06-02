# Terminal Setup Guide

---

## 🖥️ You Need 2-3 Terminals

### Terminal Layout
```
┌─────────────────────────────┐
│  Terminal 1: BACKEND SERVER │
│  python manage.py runserver │
│  (NEVER CLOSE - keeps running)
└─────────────────────────────┘
          ↑
          │ listens on localhost:8000
          │
┌─────────────────────────────┐
│  Terminal 2: TESTING/CURL   │
│  Run all curl commands here │
│  (Make API calls to Term 1) │
└─────────────────────────────┘

┌─────────────────────────────┐
│  Terminal 3: DATABASE       │
│  (Optional - for verification)
│  python manage.py shell     │
└─────────────────────────────┘
```

---

## 📋 Step-by-Step Terminal Setup

### BEFORE YOU START

**Make sure these are open:**
- ✅ Terminal 1: Backend server running
- ✅ Terminal 2: Ready for curl commands
- ✅ Terminal 3 (optional): For database checks

---

## Terminal 1: BACKEND SERVER 🚀

**Start it once and leave it running**

```bash
cd c:\Users\Sarva\Desktop\demo2\ -\ Copy\ \(2\)\backend
python manage.py runserver
```

**Expected output:**
```
System check identified no issues (0 silenced).
Starting development server at http://127.0.0.1:8000/
Quit the server with CTRL-BREAK.
```

**⚠️ IMPORTANT:**
- Keep this terminal OPEN during all testing
- Do NOT close it or press Ctrl+C
- Server responds to requests from other terminals

---

## Terminal 2: TESTING & CURL COMMANDS 🧪

**Open a NEW terminal (while Terminal 1 is running)**

```bash
cd c:\Users\Sarva\Desktop\demo2\ -\ Copy\ \(2\)\backend
```

**Now run commands in this order:**

### Step 1: Register
```bash
curl -X POST http://localhost:8000/api/register -H "Content-Type: application/json" -d "{\"username\": \"testuser\", \"password\": \"testpass123\", \"signature_algorithm\": \"RSA-SHA256\"}"
```

### Step 2: Save TOKEN
```bash
set TOKEN=<paste-token-here>
```

### Step 3: Sign Document V1
```bash
curl -X POST http://localhost:8000/api/sign-document -H "Authorization: Token %TOKEN%" -F "data=Initial version - test document" -o signed_v1.json && type signed_v1.json
```

### Step 4: Save DOC_ID
```bash
set DOC_ID=<paste-document_id-here>
```

### Step 5: Add Version 2
```bash
curl -X POST http://localhost:8000/api/add-document-version -H "Authorization: Token %TOKEN%" -F "document_id=%DOC_ID%" -F "data=Updated version - more content" -o signed_v2.json && type signed_v2.json
```

### Step 6: Add Version 3
```bash
curl -X POST http://localhost:8000/api/add-document-version -H "Authorization: Token %TOKEN%" -F "document_id=%DOC_ID%" -F "data=Final version - completed" -o signed_v3.json && type signed_v3.json
```

### Step 7: Verify Chain
```bash
curl -X POST http://localhost:8000/api/verify-document -F "file=@signed_v3.json" -s | python -m json.tool
```

✅ **All these commands run in Terminal 2**

---

## Terminal 3: DATABASE VERIFICATION 📊

**Optional - Open another NEW terminal (while Terminals 1 & 2 are running)**

```bash
cd c:\Users\Sarva\Desktop\demo2\ -\ Copy\ \(2\)\backend
python manage.py shell
```

**Then in Python shell:**

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
```

**Exit Python shell:**
```python
exit()
```

✅ **All these commands run in Terminal 3**

---

## 🎯 Complete Workflow

```
TIME    │ Terminal 1          │ Terminal 2           │ Terminal 3
────────┼─────────────────────┼──────────────────────┼──────────────
T0      │ runserver (START)   │                      │
        │ ↓ RUNNING           │                      │
────────┼─────────────────────┼──────────────────────┼──────────────
T1      │ ↓ RUNNING           │ curl register        │
        │                     │ set TOKEN            │
        │                     │ curl sign-document   │
        │                     │ set DOC_ID           │
────────┼─────────────────────┼──────────────────────┼──────────────
T2      │ ↓ RUNNING           │ curl add-version 2   │
        │                     │ curl add-version 3   │
        │                     │ curl verify-document │
────────┼─────────────────────┼──────────────────────┼──────────────
T3      │ ↓ RUNNING           │ (done)               │ manage.py shell
        │                     │                      │ verify in DB
        │                     │                      │ exit()
────────┼─────────────────────┼──────────────────────┼──────────────
END     │ Ctrl+Break to stop  │ Done                 │ Done
```

---

## ⚡ Quick Cheat Sheet

| Action | Terminal | Command |
|--------|----------|---------|
| **Start Backend** | Terminal 1 | `python manage.py runserver` |
| **Register User** | Terminal 2 | `curl -X POST http://localhost:8000/api/register ...` |
| **Save Token** | Terminal 2 | `set TOKEN=...` |
| **Sign Document** | Terminal 2 | `curl -X POST http://localhost:8000/api/sign-document ...` |
| **Add Version** | Terminal 2 | `curl -X POST http://localhost:8000/api/add-document-version ...` |
| **Verify Chain** | Terminal 2 | `curl -X POST http://localhost:8000/api/verify-document ...` |
| **Check Database** | Terminal 3 | `python manage.py shell` |

---

## 🆘 Common Issues

**"Connection refused" in Terminal 2?**
→ Make sure Terminal 1 is still running! Look for "Starting development server" output

**"Address already in use"?**
→ Backend already running. Stop it first: Press Ctrl+Break in Terminal 1, then restart

**Commands not working in wrong terminal?**
→ Make sure you're in the right terminal! Terminal 2 for curl, Terminal 1 for server

**"Token not found" error?**
→ You forgot to run `set TOKEN=...` in Terminal 2. Variables don't persist between terminals!

---

## 📌 Key Rules

1. **Terminal 1**: Backend only, never close it
2. **Terminal 2**: All curl/API commands
3. **Terminal 3**: Optional, for database verification only
4. **Variables are local**: `set TOKEN=...` only works in THAT terminal
5. **All curl commands go to Terminal 2** (uses localhost:8000 from Terminal 1)

---

## ✅ Checklist

- [ ] Terminal 1 open with backend running (`runserver` visible)
- [ ] Terminal 2 open, ready for curl commands
- [ ] Terminal 3 open (optional, for DB verification)
- [ ] All curl commands in Terminal 2 only
- [ ] TOKEN saved with `set TOKEN=...` in Terminal 2
- [ ] DOC_ID saved with `set DOC_ID=...` in Terminal 2
