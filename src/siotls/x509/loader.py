import typing

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1_modules.rfc5280 import Certificate, CertificateList, SubjectPublicKeyInfo
from pyasn1_modules.rfc5958 import PrivateKeyInfo
from pyasn1_modules.rfc6960 import BasicOCSPResponse, OCSPRequest, OCSPResponse

from .pem import pem_decode


def _load_der(data, asn_object):
    cert, rest = der_decode(data, asn_object)
    if rest:
        e =(f"only {len(data) - len(rest)} bytes out of {len(data)} "
            "could be decoded")
        raise ValueError(e)
    return cert


DerType = typing.NewType('DerType', bytes) | bytes


# Single certificate
DerCertificate = typing.NewType('DerCertificate', DerType) | bytes

def load_der_x509_certificate(data: DerCertificate) -> Certificate:
    return _load_der(data, Certificate())

def decode_pem_x509_certificate(data: bytes) -> DerCertificate:
    return pem_decode(data.decode(), 'CERTIFICATE')

def load_pem_x509_certificate(data: bytes) -> Certificate:
    return load_der_x509_certificate(decode_pem_x509_certificate(data))


# Multiple certificates
def decode_pem_x509_certificates(data: bytes) -> list[DerCertificate]:
    return pem_decode(data.encode(), 'CERTIFICATE', multi=True)

def load_pem_x509_certificates(data: bytes) -> list[Certificate]:
    return [
        load_der_x509_certificate(der_data)
        for der_data
        in decode_pem_x509_certificates(data)
    ]


# Certificate Revocation List (CRL)
DerCRL = typing.NewType('DerCRL', DerType) | bytes

def load_der_x509_crl(data: DerCRL) -> CertificateList:
    return _load_der(data, CertificateList())

def decode_pem_x509_crl(data: bytes) -> DerCRL:
    return pem_decode(data.decode(), 'X509 CRL')

def load_pem_x509_crl(data: bytes) -> CertificateList:
    return _load_der(decode_pem_x509_crl(data), CertificateList())


# OCSP
DerOCSPRequest = typing.NewType('DerOCSPRequest', DerType) | bytes
DerOCSPResponse = typing.NewType('DerOCSPResponse', DerType) | bytes
DerOCSPBasicResponse = typing.NewType('DerOCSPBasicResponse', DerType) | bytes

def load_der_ocsp_request(data: bytes) -> OCSPRequest:
    return _load_der(data, OCSPRequest())

def load_der_ocsp_response(data: DerOCSPResponse) -> OCSPResponse:
    return _load_der(data, OCSPResponse())

def load_der_ocsp_basic_response(data: DerOCSPBasicResponse) -> BasicOCSPResponse:
    return _load_der(data, BasicOCSPResponse())


# Private Key
DerPrivateKey = typing.NewType('DerPrivateKey', DerType) | bytes

def load_der_private_key(data: DerPrivateKey) -> PrivateKeyInfo:
    return _load_der(data, PrivateKeyInfo())

def decode_pem_private_key(data: bytes) -> DerPrivateKey:
    return pem_decode(data.decode(), 'PRIVATE KEY')

def load_pem_private_key(data: bytes) -> PrivateKeyInfo:
    return _load_der(decode_pem_private_key(data), PrivateKeyInfo())


# Public Key
DerPublicKey = typing.NewType('DerPublicKey', DerType) | bytes

def load_der_public_key(data: DerPublicKey) -> SubjectPublicKeyInfo:
    return _load_der(data, SubjectPublicKeyInfo())

def decode_pem_public_key(data: bytes) -> DerPublicKey:
    return pem_decode(data.decode(), 'PUBLIC KEY')

def load_pem_public_key(data: bytes):
    return _load_der(decode_pem_public_key(data), SubjectPublicKeyInfo())
