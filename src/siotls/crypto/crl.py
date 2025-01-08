from datetime import UTC, datetime
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.x509 import (
    CRLDistributionPoints,
    ExtensionNotFound,
    KeyUsage,
    load_der_x509_crl,
)

from . import TLSSignatureScheme


def get_crl_urls(certificate):
    try:
        ext = certificate.extensions.get_extension_for_class(CRLDistributionPoints)
    except ExtensionNotFound:
        return []
    urls = []
    for dist_points in ext.value:
        for url in dist_points.full_name:
            urlobj = urlsplit(url.value)
            if urlobj.scheme == 'http' and urlobj.netloc:
                urls.append(url.value)
    return urls


def load_crl(issuer, crl_der):
    crl = load_der_x509_crl(crl_der)
    validate_crl(issuer, crl)
    return crl


def validate_crl(issuer, crl):
    if crl.last_update_utc > datetime.now(UTC):
        e = "crl is not valid yet"
        raise ValueError(e)
    if crl.next_update_utc < datetime.now(UTC):
        e = "crl is expired"
        raise ValueError(e)
    if crl.issuer != issuer.subject:
        e = "wrong issuer"
        raise ValueError(e)

    try:
        key_usage = issuer.extensions.get_extension_for_class(KeyUsage)
    except ExtensionNotFound as exc:
        e = "missing mandatory Key Usage extension"
        raise ValueError(e) from exc
    if not key_usage.value.crl_sign:
        e = "issuer forbidden from signing crl"
        raise ValueError(e)

    Signature = TLSSignatureScheme.for_signature(
        issuer,
        crl.signature_algorithm_oid,
        crl.signature_hash_algorithm,
        crl.signature_algorithm_parameters,
    )
    try:
        Signature(issuer.public_key()).verify(crl.signature, crl.tbs_certlist_bytes)
    except InvalidSignature as exc:
        e = "CRL not signed by issuer"
        raise ValueError(e) from exc

    return crl.next_update_utc


def is_revoked(crl, certificate):
    return bool(crl.get_revoked_certificate_by_serial_number(certificate.serial_number))
