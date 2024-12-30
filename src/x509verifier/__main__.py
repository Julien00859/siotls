import contextlib
import re
import sys

from cryptography.x509 import load_pem_x509_certificate
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.error import PyAsn1Error
from pyasn1_modules.rfc5280 import Certificate, CertificateList
from pyasn1_modules.rfc6960 import BasicOCSPResponse, OCSPResponse

from x509oid import oid

from .pem import pem_decode

try:
    filename = sys.argv[1]
except IndexError:
    sys.exit(f"python3 -m {__package__} <file>")

cert = None
if filename.endswith('.pem'):
    with open(filename) as file:
        data = file.read()
    obj = pem_decode(data)
    with contextlib.suppress(Exception):
        cert = load_pem_x509_certificate(data.encode())
else:
    with open(filename, 'rb') as file:
        data = file.read()
    for cls in (Certificate, CertificateList, OCSPResponse, BasicOCSPResponse):
        with contextlib.suppress(PyAsn1Error):
            obj = der_decode(data, cls())[0]
            break
    else:
        obj = der_decode(data)[0]


def pformat(obj):
    return re.sub(r'\b(?:\d+\.)+\d+\b', lambda m: repr(oid(m[0])), str(obj))

print(pformat(obj))
if (
    isinstance(obj, OCSPResponse)
    and obj['responseBytes']['responseType'].asTuple() == (1, 3, 6, 1, 5, 5, 7, 48, 1, 1)
):
    ocsp = der_decode(obj['responseBytes']['response'].asOctets(), BasicOCSPResponse())[0]
    print(pformat(ocsp))
if cert:
    print(cert)
