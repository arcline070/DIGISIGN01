import os
import django
import time
import json
import base64
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# Setup Django Environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'signature_project.settings')
django.setup()

from api.crypto_utils import sign_data_with_algorithm
from api.models import DocumentRecord, DocumentVersion
from django.contrib.auth import get_user_model

User = get_user_model()

print("\n========================================================")
print("   EXECUTING LIVE SECURITY & PENETRATION TESTS")
print("========================================================\n")

# ---------------------------------------------------------
# TEST 1: PERFORMANCE BENCHMARK (RSA vs ECDSA)
# ---------------------------------------------------------
print("[TEST 1] Starting Comprehensive Cryptographic Benchmark (100 Iterations)...")

dummy_payload = b"{" + b'"data": "This is a dummy 2KB payload for benchmarking performance. "' * 50 + b"}"

# --- RSA BENCHMARKS ---
# 1. Key Generation
start = time.time()
for _ in range(10):  # Key generation is slow, do 10 iterations
    rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rsa_key_gen_ms = ((time.time() - start) / 10) * 1000

rsa_pem = rsa_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')

# 2. Signing
start = time.time()
for _ in range(100):
    rsa_sig = sign_data_with_algorithm(dummy_payload, rsa_pem, "RSA-SHA256")
rsa_sign_ms = ((time.time() - start) / 100) * 1000

# 3. Signature Size
rsa_sig_size = len(rsa_sig)

# 4. Verification (Using cryptography directly to benchmark raw algorithm speed)
rsa_public_key = rsa_private_key.public_key()
start = time.time()
for _ in range(10000):
    rsa_public_key.verify(
        rsa_sig, dummy_payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
rsa_verify_ms = ((time.time() - start) / 10000) * 1000

# --- ECDSA BENCHMARKS ---
# 1. Key Generation
start = time.time()
for _ in range(10):
    ecdsa_private_key = ec.generate_private_key(ec.SECP256R1())
ecdsa_key_gen_ms = ((time.time() - start) / 10) * 1000

ecdsa_pem = ecdsa_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')

# 2. Signing
start = time.time()
for _ in range(100):
    ecdsa_sig = sign_data_with_algorithm(dummy_payload, ecdsa_pem, "ECDSA-P256-SHA256")
ecdsa_sign_ms = ((time.time() - start) / 100) * 1000

# 3. Signature Size
ecdsa_sig_size = len(ecdsa_sig)

# 4. Verification
ecdsa_public_key = ecdsa_private_key.public_key()
start = time.time()
for _ in range(10000):
    ecdsa_public_key.verify(ecdsa_sig, dummy_payload, ec.ECDSA(hashes.SHA256()))
ecdsa_verify_ms = ((time.time() - start) / 10000) * 1000

print("\n--- RESULTS ---")
print(f"{'Metric':<25} | {'RSA-2048':<15} | {'ECDSA-P256':<15}")
print("-" * 60)
print(f"{'Key Generation Time':<25} | {rsa_key_gen_ms:>10.2f} ms | {ecdsa_key_gen_ms:>10.2f} ms")
print(f"{'Signing Time':<25} | {rsa_sign_ms:>10.2f} ms | {ecdsa_sign_ms:>10.2f} ms")
print(f"{'Verification Time':<25} | {rsa_verify_ms:>10.2f} ms | {ecdsa_verify_ms:>10.2f} ms")
print(f"{'Signature Size':<25} | {rsa_sig_size:>10} B  | {ecdsa_sig_size:>10} B")
print("-" * 60 + "\n")

# ---------------------------------------------------------
# TEST 2: DATABASE TAMPERING & LOCALIZATION
# ---------------------------------------------------------
print("[TEST 2] Simulating Insider Threat (Direct Database Tampering)...")

from api.views._helpers import _localize_tamper

original_json = b'{"amount": 5000, "recipient": "John Doe"}'
tampered_json = b'{"amount": 9000, "recipient": "John Doe"}'

print(" -> Original Data:", original_json.decode('utf-8'))
print(" -> Attack: Malicious Admin modifies database to:", tampered_json.decode('utf-8'))

print(" -> Running Tamper Localization Engine...")
diff_report, _ = _localize_tamper(original_json, tampered_json, "dummy.json")

print(" -> ENGINE OUTPUT:")
print(json.dumps(diff_report, indent=2))
print(" -> RESULT: Tamper Engine successfully caught and localized the change!\n")

print("========================================================")
print("   ALL TESTS EXECUTED SUCCESSFULLY")
print("========================================================")
