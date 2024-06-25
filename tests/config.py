import ipaddress
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from cryptography.x509.oid import NameOID
from cryptography.x509.verification import Store

from siotls import TLSConfiguration

from . import test_temp_dir

now = datetime.now(timezone.utc)
VALIDITY = timedelta(minutes=10)

key_usage_ca = x509.KeyUsage(  # cert and crl sign
    digital_signature=True, content_commitment=False, key_encipherment=False,
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
ca_privkey = ec.generate_private_key(ec.SECP256R1())
ca_pubkey = ca_privkey.public_key()
ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_pubkey)
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_subject)
    .issuer_name(ca_subject)
    .public_key(ca_pubkey)
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + VALIDITY)
    .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
    .add_extension(key_usage_ca, critical=True)
#    .add_extension(x_key_usage_ca, critical=False)
    .add_extension(
        x509.SubjectAlternativeName([x509.DNSName(ca_domain)]),
        critical=False,
    )
    .add_extension(ca_ski, critical=False)
    .sign(ca_privkey, hashes.SHA256())
)
(test_temp_dir/'ca-pubkey.pem').write_bytes(ca_pubkey.public_bytes(
    Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
(test_temp_dir/'ca-cert.pem').write_bytes(ca_cert.public_bytes(Encoding.PEM))
ca_aki = x509.AuthorityKeyIdentifier(
    ca_ski.digest, [x509.DNSName(ca_domain)], ca_cert.serial_number
)


#
# Server
#
server_domain = 'server.siotls.localhost'
server_privkey = ec.generate_private_key(ec.SECP256R1())
server_pubkey = server_privkey.public_key()
server_ski = x509.SubjectKeyIdentifier.from_public_key(server_pubkey)
server_cert = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "siotls test server"),
    ]))
    .issuer_name(ca_subject)
    .public_key(server_pubkey)
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + VALIDITY)
    .add_extension(key_usage_tls, critical=True)
    .add_extension(x_key_usage_server, critical=False)
    .add_extension(
         x509.SubjectAlternativeName([
            x509.DNSName(server_domain),
            x509.IPAddress(ipaddress.IPv4Address('127.0.0.2')),
        ]),
         critical=False,
    )
    .add_extension(ca_aki, critical=False)
    .add_extension(server_ski, critical=False)
    .sign(ca_privkey, hashes.SHA256())
)
(test_temp_dir/'server-privkey.pem').write_bytes(server_privkey.private_bytes(
    Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
(test_temp_dir/'server-pubkey.pem').write_bytes(server_pubkey.public_bytes(
    Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
(test_temp_dir/'server-cert.pem').write_bytes(server_cert.public_bytes(Encoding.PEM))

#
# Client
#
client_privkey = ec.generate_private_key(ec.SECP256R1())
client_pubkey = client_privkey.public_key()
client_ski = x509.SubjectKeyIdentifier.from_public_key(server_pubkey)
client_cert = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "siotls test client"),
    ]))
    .issuer_name(ca_subject)
    .public_key(client_pubkey)
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + VALIDITY)
    .add_extension(key_usage_tls, critical=True)
    .add_extension(x_key_usage_client, critical=False)
    .add_extension(ca_aki, critical=False)
    .add_extension(client_ski, critical=False)
    .sign(ca_privkey, hashes.SHA256())
)
(test_temp_dir/'client-privkey.pem').write_bytes(client_privkey.private_bytes(
    Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
(test_temp_dir/'client-pubkey.pem').write_bytes(client_pubkey.public_bytes(
    Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
(test_temp_dir/'client-cert.pem').write_bytes(client_cert.public_bytes(Encoding.PEM))

test_trust_store = Store([ca_cert])
test_trusted_public_keys = [client_pubkey, server_pubkey]

#
# Configurations
#
server_config = TLSConfiguration(
    'server',
    private_key=server_privkey,
    certificate_chain=[server_cert, ca_cert],
    server_hostnames=[server_domain],
)
client_config = TLSConfiguration(
    'client',
    trust_store=test_trust_store,
)
