import contextlib
import sys

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.error import PyAsn1Error
from pyasn1_modules.rfc5280 import Certificate, CertificateList
from pyasn1_modules.rfc6960 import BasicOCSPResponse, OCSPResponse

from .pem import pem_decode

try:
    filename = sys.argv[1]
except IndexError:
    sys.exit(f"python3 -m {__package__} <file>")

if filename.endswith('.pem'):
    with open(filename) as file:
        obj = pem_decode(file.read())
else:
    with open(filename, 'rb') as file:
        data = file.read()
    for cls in (Certificate, CertificateList, OCSPResponse, BasicOCSPResponse):
        with contextlib.suppress(PyAsn1Error):
            obj = der_decode(data, cls())[0]
            break
    else:
        obj = der_decode(data)[0]

print(obj)  # noqa: T201
if (
    isinstance(obj, OCSPResponse)
    and obj['responseBytes']['responseType'].asTuple() == (1, 3, 6, 1, 5, 5, 7, 48, 1, 1)
):
    ocsp = der_decode(obj['responseBytes']['response'].asOctets(), BasicOCSPResponse())[0]
    print(ocsp)  # noqa: T201
