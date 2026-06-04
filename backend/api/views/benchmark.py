import time
import json
import io
import difflib
import hashlib
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from ._helpers import _json_localization_diff, _normalize_text_for_diff
from api.crypto_utils import create_key_pair


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def system_benchmark(request):
    """
    Isolated Full-Stack Performance Benchmarking endpoint.
    Runs three analytical tests sequentially.
    """
    import pandas as pd

    # --- TEST 1: Cryptographic Showdown ---
    # Use raw cryptography key objects to bypass PEM re-parsing on every call.
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding as asym_padding
    from cryptography.hazmat.backends import default_backend

    iterations = 1000

    # Generate keys ONCE, outside any timer
    rsa_priv_pem, rsa_pub_pem = create_key_pair("RSA-SHA256")
    ecdsa_priv_pem, ecdsa_pub_pem = create_key_pair("ECDSA-P256-SHA256")

    # Load key OBJECTS once — this is not part of the benchmark
    rsa_priv_key = serialization.load_pem_private_key(rsa_priv_pem.encode(), password=None, backend=default_backend())
    rsa_pub_key = serialization.load_pem_public_key(rsa_pub_pem.encode(), backend=default_backend())
    ecdsa_priv_key = serialization.load_pem_private_key(ecdsa_priv_pem.encode(), password=None, backend=default_backend())
    ecdsa_pub_key = serialization.load_pem_public_key(ecdsa_pub_pem.encode(), backend=default_backend())

    # Pre-generate UNIQUE payloads to defeat OpenSSL caching
    # Each payload has loop index + high-res timestamp entropy
    unique_payloads = [f"benchmark_payload_{i}_{time.perf_counter()}".encode() for i in range(iterations)]

    # --- RSA-PSS Sign (3072-bit) ---
    rsa_signatures = [None] * iterations
    t_start = time.perf_counter()
    for i in range(iterations):
        rsa_signatures[i] = rsa_priv_key.sign(
            unique_payloads[i],
            asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    rsa_sign_ms = ((time.perf_counter() - t_start) / iterations) * 1000

    # --- RSA-PSS Verify (3072-bit) ---
    t_start = time.perf_counter()
    for i in range(iterations):
        rsa_pub_key.verify(
            rsa_signatures[i],
            unique_payloads[i],
            asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    rsa_verify_ms = ((time.perf_counter() - t_start) / iterations) * 1000

    # --- ECDSA Sign (P-256) ---
    ecdsa_signatures = [None] * iterations
    t_start = time.perf_counter()
    for i in range(iterations):
        ecdsa_signatures[i] = ecdsa_priv_key.sign(unique_payloads[i], ec.ECDSA(hashes.SHA256()))
    ecdsa_sign_ms = ((time.perf_counter() - t_start) / iterations) * 1000

    # --- ECDSA Verify (P-256) ---
    t_start = time.perf_counter()
    for i in range(iterations):
        ecdsa_pub_key.verify(ecdsa_signatures[i], unique_payloads[i], ec.ECDSA(hashes.SHA256()))
    ecdsa_verify_ms = ((time.perf_counter() - t_start) / iterations) * 1000


    # --- TEST 2: Diff Engine Stress Test ---
    # Setup 100-row dummy data
    original_data = [{"id": i, "name": f"Employee {i}", "department": "Engineering", "salary": 100000 + i * 100} for i in range(100)]
    tampered_data = [{"id": i, "name": f"Employee {i}", "department": "Engineering", "salary": (100000 + i * 100) if i != 50 else 999999} for i in range(100)]
    
    # 1. JSON Diff Test
    json_orig = json.dumps(original_data)
    json_tamp = json.dumps(tampered_data)
    
    start = time.perf_counter()
    for _ in range(10): # Run 10 times to get a stable average
        _json_localization_diff(json_orig, json_tamp)
    diff_json_ms = ((time.perf_counter() - start) / 10) * 1000

    # 2. Excel Binary + Openpyxl Diff Test
    df_orig = pd.DataFrame(original_data)
    df_tamp = pd.DataFrame(tampered_data)
    
    buf_orig = io.BytesIO()
    buf_tamp = io.BytesIO()
    df_orig.to_excel(buf_orig, index=False)
    df_tamp.to_excel(buf_tamp, index=False)
    excel_orig_bytes = buf_orig.getvalue()
    excel_tamp_bytes = buf_tamp.getvalue()

    start = time.perf_counter()
    for _ in range(10): # Run 10 times to get a stable average
        norm_orig, _ = _normalize_text_for_diff(excel_orig_bytes, "data.xlsx")
        norm_tamp, _ = _normalize_text_for_diff(excel_tamp_bytes, "data.xlsx")
        difflib.SequenceMatcher(a=norm_orig.splitlines(), b=norm_tamp.splitlines()).get_opcodes()
    diff_excel_ms = ((time.perf_counter() - start) / 10) * 1000


    # --- TEST 3: Hash Chain Latency ---
    # CPU Warmup to prevent Cold Start anomaly
    _ = hashlib.sha256(b"warmup").hexdigest()

    chain_lengths = [1, 10, 25, 50]
    chain_results = {}
    
    for length in chain_lengths:
        # Pre-generate exact payloads to avoid string I/O pollution in the timer
        chain_payloads = [f"Historical Document Version {i} Data".encode() for i in range(length)]
        
        start = time.perf_counter()
        # Maintain the global iterations scaling (1000)
        for _ in range(iterations):
            current_hash = b"genesis_hash"
            for i in range(length):
                current_hash = hashlib.sha256(current_hash + chain_payloads[i]).hexdigest().encode()
        chain_results[f"chain_{length}_ms"] = ((time.perf_counter() - start) / iterations) * 1000


    return Response(
        {
            "crypto": {
                "rsa_sign_ms": rsa_sign_ms,
                "rsa_verify_ms": rsa_verify_ms,
                "ecdsa_sign_ms": ecdsa_sign_ms,
                "ecdsa_verify_ms": ecdsa_verify_ms,
            },
            "diff": {
                "diff_json_ms": diff_json_ms,
                "diff_excel_ms": diff_excel_ms,
            },
            "chain": chain_results
        }
    )
