from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone
import base64

def create_ca_key_pair():
    \"\"\"Create CA private key and self-signed cert.\"\"\"
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    ca_pub = ca_key.public_key()
    
    # CA subject
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
    \"\"\"Create CSR for user cert.\"\"\"
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

def sign_csr(ca_priv_pem: str, csr_pem: str, username: str):
    \"\"\"CA signs user CSR.\"\"\"
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
    \"\"\"Get pubkey PEM from cert for verify.\"\"\"
    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
    pub = cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return pub
