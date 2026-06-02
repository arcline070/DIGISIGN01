from django.urls import path

from . import views

urlpatterns = [
    path("register", views.register, name="register"),
    path("login", views.login_view, name="login"),
    path("logout", views.logout_view, name="logout"),
    path("my-public-key", views.my_public_key, name="my_public_key"),
    path("set-signature-algorithm", views.set_signature_algorithm, name="set_signature_algorithm"),
    path("supported-algorithms", views.supported_algorithms, name="supported_algorithms"),
    path("timestamp", views.timestamp, name="timestamp"),
    path("benchmark-crypto", views.benchmark_crypto, name="benchmark_crypto"),
    path("verify-chain", views.verify_chain, name="verify_chain"),
    path("verify-qr", views.verify_qr, name="verify_qr"),
    path("integrity-report", views.integrity_report, name="integrity_report"),
    path("sign", views.sign, name="sign"),
    path("logs", views.logs, name="logs"),
    path("verify", views.verify, name="verify"),
    path("export", views.export_signed, name="export"),
    # New signed-package endpoints
    path("sign-document", views.sign_document, name="sign_document"),
    path("add-document-version", views.add_document_version, name="add_document_version"),
    path("my-document-ids", views.my_document_ids, name="my_document_ids"),
    path("my-document-ids-with-metadata", views.my_document_ids_with_metadata, name="my_document_ids_with_metadata"),
    path("verify-document", views.verify_document, name="verify_document"),
    path("verify-stored-document", views.verify_stored_document, name="verify_stored_document"),
    path("verify-and-watermark", views.verify_and_watermark, name="verify_and_watermark"),
]
