"""
RSA + SHA-256 signing (PKCS1v15) and verification helpers + PKI support.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
from typing import Literal, Tuple, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone
import time

DataInput = Union[str, bytes]
AlgorithmName = Literal["RSA-SHA256", "ECDSA-P256-SHA256"]

logger = logging.getLogger(__name__)

# Original functions unchanged
def sha256_hex(data: DataInput) -> str:
    if isinstance(data, str):
        payload = data.encode("utf-8")
    else:
        payload = data
    return hashlib.sha256(payload).hexdigest()

def normalize_signable_payload(raw: str) -> str:
    if raw is None:
        return ""
    s = str(raw)
    try:
        obj = json.loads(s)
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (json.JSONDecodeError, TypeError, ValueError):
        return s

def create_rsa_pem_pair() -> Tuple[str, str]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def create_ecdsa_pem_pair() -> Tuple[str, str]:
    private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def create_key_pair(algorithm: AlgorithmName) -> Tuple[str, str]:
    if algorithm == "RSA-SHA256":
        return create_rsa_pem_pair()
    if algorithm == "ECDSA-P256-SHA256":
        return create_ecdsa_pem_pair()
    raise ValueError(f"Unsupported algorithm: {algorithm}")

def normalize_external_public_key_pem(pem_input: str) -> tuple[str | None, str | None]:
    raw = (pem_input or "").strip()
    if not raw:
        return None, "Public key is required for verification."
    try:
        serialization.load_pem_public_key(raw.encode("utf-8"), backend=default_backend())
        return raw, None
    except Exception:
        return None, "Invalid public key PEM."

def sign_data(data: DataInput, private_pem: str) -> bytes:
    return sign_data_with_algorithm(data, private_pem, "RSA-SHA256")


def sign_data_with_algorithm(
    data: DataInput, private_pem: str, algorithm: AlgorithmName
) -> bytes:
    if isinstance(data, str):
        payload = data.encode("utf-8")
    else:
        payload = data

    private_key = serialization.load_pem_private_key(
        private_pem.encode("utf-8"),
        password=None,
        backend=default_backend(),
    )
    if algorithm == "RSA-SHA256":
        return private_key.sign(
            payload,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    if algorithm == "ECDSA-P256-SHA256":
        return private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    raise ValueError(f"Unsupported algorithm: {algorithm}")

def verify_signature(public_key_pem: str, signature_base64: str, data_bytes: DataInput) -> bool:
    return verify_signature_with_algorithm(
        public_key_pem, signature_base64, data_bytes, "RSA-SHA256"
    )


def verify_signature_with_algorithm(
    public_key_pem: str,
    signature_base64: str,
    data_bytes: DataInput,
    algorithm: AlgorithmName,
) -> bool:
    try:
        if isinstance(data_bytes, str):
            payload = data_bytes.encode("utf-8")
        else:
            payload = data_bytes
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8"),
            backend=default_backend(),
        )
        signature = base64.b64decode(signature_base64, validate=True)
        if algorithm == "RSA-SHA256":
            public_key.verify(
                signature,
                payload,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        elif algorithm == "ECDSA-P256-SHA256":
            public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        return True
    except Exception as e:
        logger.warning("Signature verification failed: %s", e)
        return False

# NEW PKI FUNCTIONS
def create_ca_key_pair():
    """Create CA private key and self-signed cert (DEMO CA)."""
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    ca_pub = ca_key.public_key()
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'DEMO CA'),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365*10))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    
    return (
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode(),
        cert.public_bytes(serialization.Encoding.PEM).decode()
    )

def create_user_csr(priv_pem: str, username: str):
    """Create CSR for user cert."""
    priv_key = serialization.load_pem_private_key(
        priv_pem.encode(),
        password=None,
        backend=default_backend()
    )
    
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, username)])
    )
    
    csr = csr_builder.sign(priv_key, hashes.SHA256(), default_backend())
    return csr.public_bytes(serialization.Encoding.PEM).decode()

def sign_csr(ca_priv_pem: str, csr_pem: str):
    """CA signs user CSR."""
    ca_priv = serialization.load_pem_private_key(
        ca_priv_pem.encode(),
        password=None,
        backend=default_backend()
    )
    csr = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'DEMO CA')]))
    builder = builder.not_valid_before(datetime.now(timezone.utc))
    builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
    builder = builder.public_key(csr.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    )
    cert = builder.sign(ca_priv, hashes.SHA256(), default_backend())
    
    return cert.public_bytes(serialization.Encoding.PEM).decode()

def extract_pub_from_cert(cert_pem: str):
    """Get pubkey PEM from cert for signing/verify."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    pub = cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return pub

def mock_timestamp_token():
    """Mock TSA token (base64 encoded time hash)."""
    ts_data = f"TS:{int(time.time())}|hash:SHA256".encode()
    return base64.b64encode(ts_data).decode()
