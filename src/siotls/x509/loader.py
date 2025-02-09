import typing

import pyasn1_modules.rfc4055  # RSA algorithms
import pyasn1_modules.rfc5480  # ECDSA algorithms # noqa: F401
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.native.decoder import decode as py_decode
from pyasn1_modules.rfc5280 import (
    AlgorithmIdentifier,
    Certificate,
    CertificateList,
    SubjectPublicKeyInfo,
    algorithmIdentifierMap,
)
from pyasn1_modules.rfc5958 import PrivateKeyInfo
from pyasn1_modules.rfc6960 import BasicOCSPResponse, OCSPRequest, OCSPResponse

from . import oid
from .pem import pem_decode


def load_der(data, asn_object):
    """
    :meta private:
    """
    cert, rest = der_decode(data, asn_object)
    if rest:
        e =(f"only {len(data) - len(rest)} bytes out of {len(data)} "
            "could be decoded")
        raise ValueError(e)
    return cert


# Single certificate
DerCertificate = typing.NewType('DerCertificate', bytes)  #:
PemCertificate = typing.NewType('PemCertificate', bytes)  #:
PemCertificates = typing.NewType('PemCertificates', bytes)  #:

def load_der_certificate(data: DerCertificate) -> Certificate:
    return load_der(data, Certificate())

def decode_pem_certificate(data: PemCertificate) -> DerCertificate:
    return pem_decode(data.decode(), 'CERTIFICATE')

def load_pem_certificate(data: PemCertificate) -> Certificate:
    return load_der_certificate(decode_pem_certificate(data))


# Multiple certificates
def load_der_certificates(data_list: list[DerCertificate]) -> list[Certificate]:
    return [load_der(data, Certificate()) for data in data_list]

def decode_pem_certificates(data: PemCertificates) -> list[DerCertificate]:
    return list(pem_decode(data.decode(), 'CERTIFICATE', multi=True))

def load_pem_certificates(data: PemCertificates) -> list[Certificate]:
    return load_der_certificates(decode_pem_certificates(data))


# Certificate Revocation List (CRL)
DerCRL = typing.NewType('DerCRL', bytes)  #:
PemCRL = typing.NewType('PemCRL', bytes)  #:

def load_der_crl(data: DerCRL) -> CertificateList:
    return load_der(data, CertificateList())

def decode_pem_crl(data: PemCRL) -> DerCRL:
    return pem_decode(data.decode(), 'X509 CRL')

def load_pem_crl(data: PemCRL) -> CertificateList:
    return load_der_crl(decode_pem_crl(data))


# OCSP
DerOCSPRequest = typing.NewType('DerOCSPRequest', bytes)  #:
DerOCSPResponse = typing.NewType('DerOCSPResponse', bytes)  #:
DerOCSPBasicResponse = typing.NewType('DerOCSPBasicResponse', bytes)  #:

def load_der_ocsp_request(data: DerOCSPRequest) -> OCSPRequest:
    return load_der(data, OCSPRequest())

def load_der_ocsp_response(data: DerOCSPResponse) -> OCSPResponse:
    return load_der(data, OCSPResponse())

def load_der_ocsp_basic_response(data: DerOCSPBasicResponse) -> BasicOCSPResponse:
    return load_der(data, BasicOCSPResponse())


# Private Key
DerPrivateKey = typing.NewType('DerPrivateKey', bytes)  #:
PemPrivateKey = typing.NewType('PemPrivateKey', bytes)  #:

def load_der_private_key(data: DerPrivateKey) -> PrivateKeyInfo:
    return load_der(data, PrivateKeyInfo())

def decode_pem_private_key(data: PemPrivateKey) -> DerPrivateKey:
    return pem_decode(data.decode(), 'PRIVATE KEY')

def load_pem_private_key(data: PemPrivateKey) -> PrivateKeyInfo:
    return load_der(decode_pem_private_key(data), PrivateKeyInfo())


# Public Key
DerPublicKey = typing.NewType('DerPublicKey', bytes)  #:
PemPublicKey = typing.NewType('PemPublicKey', bytes)  #:

def load_der_public_key(data: DerPublicKey) -> SubjectPublicKeyInfo:
    return load_der(data, SubjectPublicKeyInfo())

def decode_pem_public_key(data: PemPublicKey) -> DerPublicKey:
    return pem_decode(data.decode(), 'PUBLIC KEY')

def load_pem_public_key(data: PemPublicKey) -> SubjectPublicKeyInfo:
    return load_der(decode_pem_public_key(data), SubjectPublicKeyInfo())


def load_algorithm(
    AlgoOID: oid.PublicKeyAlgorithmOID | oid.SignatureAlgorithmOID,  # noqa: N803
    algo: AlgorithmIdentifier,
):
    algo_oid = oid.from_pyasn1(AlgoOID, algo['algorithm'])
    try:
        spec = algorithmIdentifierMap[algo['algorithm']]
    except KeyError:
        return algo_oid, None  # no parameters
    if not algo['parameters'].hasValue():
        return algo_oid, py_decode({}, spec)  # missing parameters
    return algo_oid, load_der(algo['parameters'], spec)
