from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1_modules.rfc5280 import Certificate, CertificateList
from pyasn1_modules.rfc6960 import OCSPRequest, OCSPResponse

from .pem import pem_decode


def _load_der(data, asn_object):
    cert, rest = der_decode(data, asn_object)
    if rest:
        e =(f"only {len(data) - len(rest)} bytes out of {len(data)} "
            "could be decoded")
        raise ValueError(e)
    return cert


def load_pem_x509_certificate(data):
    return pem_decode(data, Certificate())


def load_pem_x509_certificates(data):
    return pem_decode(data, Certificate(), multi=True)


def load_der_x509_certificate(data):
    return _load_der(data, Certificate())


def load_pem_x509_crl(data):
    return pem_decode(data, CertificateList())


def load_der_x509_crl(data):
    return _load_der(data, CertificateList())


def load_der_ocsp_request(data):
    return _load_der(data, OCSPRequest())


def load_der_ocsp_response(data):
    return _load_der(data, OCSPResponse())
