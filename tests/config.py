from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from cryptography.x509.verification import Store
from siotls import TLSConfiguration

now = datetime.now(timezone.utc)
key_usage_ca = x509.KeyUsage(  # cert and crl sign
    digital_signature=False, content_commitment=False, key_encipherment=False,
    data_encipherment=False, key_agreement=False, key_cert_sign=True,
    crl_sign=True, encipher_only=False, decipher_only=False,
)
key_usage_tls = x509.KeyUsage(  # digital signature
    digital_signature=True, content_commitment=False, key_encipherment=False,
    data_encipherment=False, key_agreement=False, key_cert_sign=False,
    crl_sign=False, encipher_only=False, decipher_only=False,
)
x_key_usage_ca = x509.ExtendedKeyUsage([
    x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING,
    x509.oid.ExtendedKeyUsageOID.TIME_STAMPING,
])
x_key_usage_client = x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH])
x_key_usage_server = x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH])

#
# CA
#
ca_domain = 'ca.siotls.localhost'
ca_subject = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "siotls test CA"),
])
ca_privkey = Ed25519PrivateKey.generate()
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_subject)
    .issuer_name(ca_subject)
    .public_key(ca_privkey.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + timedelta(minutes=10))
    .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
    .add_extension(key_usage_ca, critical=True)
    .add_extension(x_key_usage_ca, critical=False)
    .add_extension(
        x509.SubjectAlternativeName([x509.DNSName(ca_domain)]),
        critical=False,
    )
    .sign(ca_privkey, None)
)

#
# Server
#
server_domain = 'server.siotls.localhost'
server_privkey = Ed25519PrivateKey.generate()
server_cert = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "siotls test server"),
    ]))
    .issuer_name(ca_subject)
    .public_key(server_privkey.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + timedelta(minutes=10))
    .add_extension(key_usage_tls, critical=True)
    .add_extension(x_key_usage_server, critical=False)
    .add_extension(
         x509.SubjectAlternativeName([x509.DNSName(server_domain)]),
         critical=False,
    )
    .sign(ca_privkey, None)
)

#
# Client
#
client_privkey = Ed25519PrivateKey.generate()
client_cert = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "siotls test client"),
    ]))
    .issuer_name(ca_subject)
    .public_key(server_privkey.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + timedelta(minutes=10))
    .add_extension(key_usage_tls, critical=True)
    .add_extension(x_key_usage_client, critical=False)
    .sign(ca_privkey, None)
)
