__all__ = ['get_ocsp_url', 'make_ocsp_request', 'validate_ocsp']

from datetime import UTC, datetime
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ExtendedKeyUsage, ExtensionNotFound
from cryptography.x509.ocsp import (
    OCSPCertStatus,
    OCSPRequestBuilder,
    OCSPResponseStatus,
    load_der_ocsp_request,
    load_der_ocsp_response,
)
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    ExtensionOID,
)

from . import TLSSignatureSuite

AIA = ExtensionOID.AUTHORITY_INFORMATION_ACCESS
OCSP = AuthorityInformationAccessOID.OCSP


def get_ocsp_url(certificate):
    try:
        ext = certificate.extensions.get_extension_for_oid(AIA)
    except ExtensionNotFound:
        return None
    for access_description in ext.value:
        if access_description.access_method == OCSP:
            url = access_description.access_location.value
            urlobj = urlsplit(url)
            if urlobj.scheme == 'http' and urlobj.netloc:
                return url
    return None


def make_ocsp_request(certificate, issuer, digestmod=SHA1) -> bytes:
    return (
        OCSPRequestBuilder()
        .add_certificate(certificate, issuer, digestmod())
        .build()
        .public_bytes(Encoding.DER)
    )

def validate_ocsp(issuer, ocsp_request: bytes, ocsp_response: bytes):  # noqa: C901
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
    if res.this_update_utc > datetime.now(UTC):
        e = "response is not valid yet"
        raise ValueError(e)
    if res.next_update_utc < datetime.now(UTC):
        e = "response is expired"
        raise ValueError(e)

    try:
        ext_key_usage = issuer.extensions.get_extension_for_class(ExtendedKeyUsage)
    except ExtensionNotFound as exc:
        e = "missing mandatory Extended Key Usage (EKU) extension"
        raise ValueError(e) from exc
    if not ExtendedKeyUsageOID.OCSP_SIGNING not in ext_key_usage.value:
        e = "issuer forbidden from signing OCSP"
        raise ValueError(e)

    Signature = TLSSignatureSuite.for_signature(  # noqa: N806
        issuer,
        res.signature_algorithm_oid,
        res.signature_hash_algorithm,
    )
    try:
        Signature(issuer.public_key()).verify(res.signature, res.tbs_response_bytes)
    except InvalidSignature as exc:
        e = "OCSP not signed by issuer"
        raise ValueError(e) from exc
    return res.next_update_utc
