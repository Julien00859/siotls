from datetime import datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.ocsp import (
    OCSPCertStatus,
    OCSPRequestBuilder,
    OCSPResponseStatus,
    load_der_ocsp_request,
    load_der_ocsp_response,
)
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from siotls.crypto.signatures import TLSSignatureSuite

AIA = ExtensionOID.AUTHORITY_INFORMATION_ACCESS
OCSP = AuthorityInformationAccessOID.OCSP


def get_ocsp_url(certificate):
    return next(
        access_description.access_location.value
        for access_description
        in certificate.extensions.get_extension_for_oid(AIA).value
        if access_description.access_method == OCSP
    )

def make_ocsp_request(certificate, issuer, digestmod=SHA1) -> bytes:
    return (
        OCSPRequestBuilder()
        .add_certificate(certificate, issuer, digestmod())
        .build()
        .public_bytes(Encoding.DER)
    )

def validate_ocsp(issuer, ocsp_request: bytes, ocsp_response: bytes):
    req = load_der_ocsp_request(ocsp_request)
    res = load_der_ocsp_response(ocsp_response)

    if res.response_status != OCSPResponseStatus.SUCCESSFUL:
        e = "response status is not successful"
        raise ValueError(e)

    if res.certificate_status != OCSPCertStatus.GOOD:
        e = "certificate status is not good"
        raise ValueError(e)

    if res.issuer_name_hash != req.issuer_name_hash:
        e = "request and response issuer name mismatch"
        raise ValueError(e)

    if res.issuer_key_hash != req.issuer_key_hash:
        e = "request and response issuer key mismatch"
        raise ValueError(e)

    if res.serial_number != req.serial_number:
        e = "request and response serial number mismatch"
        raise ValueError(e)

    if res.this_update > datetime.utcnow():
        e = "response is not valid yet"
        raise ValueError(e)

    if res.next_update < datetime.utcnow():
        e = "response is expired"
        raise ValueError(e)

    if res.signature_algorithm_oid != issuer.signature_algorithm_oid:
        e = "request and response signature algorithm mismatch"
        raise ValueError(e)

    if res.signature_hash_algorithm != issuer.signature_hash_algorithm:
        e = "request and response hash algorithm mismatch"
        raise ValueError(e)

    try:
        TLSSignatureSuite.from_cert(issuer).verify(
            res.signature,
            res.tbs_response_bytes,
        )
    except InvalidSignature as exc:
        raise ValueError(exc.args[0]) from exc
