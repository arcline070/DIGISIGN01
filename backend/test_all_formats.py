import os
import django
import json
import pandas as pd
from io import BytesIO

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'signature_project.settings')
django.setup()

from django.contrib.auth import get_user_model
from api.views._helpers import _localize_tamper

User = get_user_model()
user = User.objects.filter(profile__isnull=False).first()

def test_format(name, original_bytes, tampered_bytes, filename):
    print(f"\n==============================")
    print(f"--- Testing Format: {name} ---")
    
    tamper_report, err_msg = _localize_tamper(original_bytes, tampered_bytes, filename)
    
    if err_msg:
        print(f"[-] NO DETAILED TAMPER REPORT for {name}! (Basic Hash mismatch only)")
        print(f"    Error: {err_msg}")
    elif tamper_report and any(tamper_report.values()):
        print(f"[+] Tamper Localization WORKS for {name}:")
        print(json.dumps(tamper_report, indent=2))
    else:
        print(f"[-] Tamper report is empty for {name}")

# JSON
json_orig = b'{"name": "Alice", "age": 30}'
json_tamp = b'{"name": "Alice", "age": 31}'
test_format("JSON", json_orig, json_tamp, "test.json")

# TXT
txt_orig = b'Line 1\nLine 2\nLine 3'
txt_tamp = b'Line 1\nLine Modified\nLine 3'
test_format("TXT", txt_orig, txt_tamp, "test.txt")

# CSV
csv_orig = b'id,name\n1,Alice\n2,Bob'
csv_tamp = b'id,name\n1,Alice\n2,Charlie'
test_format("CSV", csv_orig, csv_tamp, "test.csv")

# Excel (XLSX)
df = pd.DataFrame({'id': [1, 2], 'name': ['Alice', 'Bob']})
b_orig = BytesIO()
df.to_excel(b_orig, index=False)

df_tamp = pd.DataFrame({'id': [1, 2], 'name': ['Alice', 'Charlie']})
b_tamp = BytesIO()
df_tamp.to_excel(b_tamp, index=False)

test_format("EXCEL", b_orig.getvalue(), b_tamp.getvalue(), "test.xlsx")
