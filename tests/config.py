from cryptography import x509
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.verification import Store

from siotls import TLSConfiguration

from . import test_pem_dir


def get_san_values(certificate, types=(x509.DNSName, x509.IPAddress)):
    san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    values = []
    for type_ in types:
        values.extend(san.value.get_values_for_type(type_))
    return values


ca_cert = load_pem_x509_certificate((test_pem_dir/'ca-cert.pem').read_bytes())

client_pubkey = load_pem_public_key((test_pem_dir/'client-pubkey.pem').read_bytes())
client_privkey = load_pem_private_key((test_pem_dir/'client-privkey.pem').read_bytes(), None)
client_cert = load_pem_x509_certificate((test_pem_dir/'client-cert.pem').read_bytes())

server_pubkey = load_pem_public_key((test_pem_dir/'server-pubkey.pem').read_bytes())
server_privkey = load_pem_private_key((test_pem_dir/'server-privkey.pem').read_bytes(), None)
server_cert = load_pem_x509_certificate((test_pem_dir/'server-cert.pem').read_bytes())

test_trust_store = Store([ca_cert])
test_trusted_public_keys = [client_pubkey, server_pubkey]

#
# Configurations
#
server_config = TLSConfiguration(
    'server',
    private_key=server_privkey,
    certificate_chain=[server_cert, ca_cert],
    server_hostnames=get_san_values(server_cert),
)
client_config = TLSConfiguration(
    'client',
    trust_store=test_trust_store,
)
