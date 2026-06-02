"""
Views package for the Digital Signature Engine API.

Re-exports all public view functions so that ``from .views import X``
in urls.py continues to work unchanged.
"""

from .auth import (
    login_view,
    logout_view,
    my_public_key,
    register,
    set_signature_algorithm,
    supported_algorithms,
    timestamp,
)
from .signing import (
    add_document_version,
    my_document_ids,
    my_document_ids_with_metadata,
    sign,
    sign_document,
)
from .verification import (
    integrity_report,
    verify,
    verify_and_watermark,
    verify_chain,
    verify_document,
    verify_qr,
    verify_stored_document,
)
from .export import (
    benchmark_crypto,
    export_signed,
    logs,
)

__all__ = [
    # Auth
    "register",
    "login_view",
    "logout_view",
    "my_public_key",
    "set_signature_algorithm",
    "supported_algorithms",
    "timestamp",
    # Signing
    "sign",
    "sign_document",
    "add_document_version",
    "my_document_ids",
    "my_document_ids_with_metadata",
    # Verification
    "verify",
    "verify_document",
    "verify_stored_document",
    "verify_and_watermark",
    "verify_chain",
    "verify_qr",
    "integrity_report",
    # Export
    "export_signed",
    "logs",
    "benchmark_crypto",
]
