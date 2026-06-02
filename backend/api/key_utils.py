"""Ensure each Django user has a persisted RSA key pair + self-signed certificate."""

import base64
import hashlib
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from django.conf import settings
from django.contrib.auth import get_user_model

from .crypto_utils import (
    AlgorithmName,
    create_key_pair,
)
from .models import UserProfile

User = get_user_model()


def _fernet() -> Fernet:
    env_key = (getattr(settings, "PRIVATE_KEY_FERNET_KEY", "") or "").strip()
    if env_key:
        return Fernet(env_key.encode("utf-8"))
    # Dev fallback to keep app runnable; production should always set PRIVATE_KEY_FERNET_KEY.
    derived = hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(derived))


def encrypt_private_key(private_key: str) -> str:
    return _fernet().encrypt(private_key.encode("utf-8")).decode("utf-8")


def decrypt_private_key(encrypted_private_key: str) -> str:
    return _fernet().decrypt(encrypted_private_key.encode("utf-8")).decode("utf-8")


def _create_self_signed_user_certificate(private_key_pem: str, username: str) -> str:
    """
    Create a self-signed X.509 certificate for the given user.

    Subject/issuer:
      - Country: IN
      - Organization: NIC Digital Signature System
      - Common Name (CN): username
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None,
    )
    public_key = private_key.public_key()

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME, "NIC Digital Signature System"
            ),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def ensure_user_profile(
    user: User, preferred_algorithm: AlgorithmName | None = None
) -> UserProfile:
    """Create persisted keys + one self-signed cert per user."""
    existing = UserProfile.objects.filter(user=user).first()
    target_algo = preferred_algorithm or UserProfile.SignatureAlgorithm.RSA
    if existing:
        update_fields: list[str] = []
        if not getattr(existing, "signature_algorithm", ""):
            existing.signature_algorithm = target_algo
            update_fields.append("signature_algorithm")

        # Optional algorithm upgrade (step-wise objective support).
        if preferred_algorithm and existing.signature_algorithm != preferred_algorithm:
            priv, pub = create_key_pair(preferred_algorithm)
            cert_pem = _create_self_signed_user_certificate(priv, user.username)
            existing.private_key = encrypt_private_key(priv)
            existing.public_key = pub
            existing.certificate = cert_pem
            existing.certificate_pem = cert_pem
            existing.signature_algorithm = preferred_algorithm
            existing.save(
                update_fields=[
                    "private_key",
                    "public_key",
                    "certificate",
                    "certificate_pem",
                    "signature_algorithm",
                ]
            )
            return existing

        # Backfill/repair certificate if missing or not self-signed.
        certificate_pem = (existing.certificate or "").strip() or (existing.certificate_pem or "").strip()
        needs_regen = False
        if not certificate_pem:
            needs_regen = True
        else:
            try:
                cert = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
                needs_regen = cert.issuer != cert.subject
            except Exception:
                needs_regen = True

        if needs_regen:
            private_key_pem = decrypt_private_key(existing.private_key)
            new_cert_pem = _create_self_signed_user_certificate(private_key_pem, user.username)
            existing.certificate = new_cert_pem
            existing.certificate_pem = new_cert_pem
            update_fields.extend(["certificate", "certificate_pem"])
        if update_fields:
            existing.save(update_fields=update_fields)
        return existing

    # Generate user keypair
    priv, pub = create_key_pair(target_algo)
    cert_pem = _create_self_signed_user_certificate(priv, user.username)

    profile = UserProfile.objects.create(
        user=user,
        private_key=encrypt_private_key(priv),
        public_key=pub,
        certificate=cert_pem,
        certificate_pem=cert_pem,
        signature_algorithm=target_algo,
        role=UserProfile.Role.ADMIN if user.is_superuser or user.is_staff else UserProfile.Role.USER,
    )
    return profile
