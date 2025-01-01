# class names
# ruff: noqa: N801
import abc
from collections import defaultdict
from typing import Any, ClassVar, Literal

from siotls.iana import SignatureScheme
from siotls.utils import RegistryMeta
from siotls.x509.loader import load_subject_key_info_algorithm
from siotls.x509.oid import (
    EllipticCurveOID,
    HashOID,
    PublicKeyAlgorithmOID,
    SignatureAlgorithmOID,
    from_pyasn1,
)

DIGEST_NAME = Literal['sha256', 'sha384', 'sha512']
PADDING_NAME = Literal['EMSA-PKCS1-v1_5', 'EMSA-PSS']


class ISign(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def sign(self, message):
        raise NotImplementedError

    @abc.abstractmethod
    def verify(self, signature, message):
        raise NotImplementedError


class TLSSignatureSuite(ISign, metaclass=RegistryMeta):
    _registry_key = '_signature_iana_registry'
    _signature_iana_registry: ClassVar = {}
    _signature_algo_registry: ClassVar = {}
    _signature_pubkey_oid_registry: ClassVar = defaultdict(list)

    iana_id: SignatureScheme
    sign_oid: SignatureAlgorithmOID
    pubkey_id: PublicKeyAlgorithmOID
    curve_oid: EllipticCurveOID | None
    digest_name: DIGEST_NAME | None
    padding_name: PADDING_NAME | None
    _key: Any

    def __init_subclass__(cls, *, register=True, **kwargs):
        super().__init_subclass__(**kwargs)
        if register and TLSSignatureSuite in cls.__bases__:
            cls._signature_iana_registry[cls.iana_id] = cls
            cls._signature_algo_registry[(
                cls.sign_oid,
                cls.curve_oid,
                cls.digest_name,
                cls.padding_name
            )] = cls

    def __init__(self, key):
        self._key = key

    @classmethod
    def for_certificate(cls, asn1_certificate):
        return cls.for_key(asn1_certificate['tbsCertificate']['subjectPublicKeyInfo'])

    @classmethod
    def for_subject_key_info(cls, asn1_subject_key_info):
        pubkey_oid, params = load_subject_key_info_algorithm(asn1_subject_key_info)
        Suites = cls._signature_pubkey_oid_registry[pubkey_oid]
        if pubkey_oid == PublicKeyAlgorithmOID.EC_PUBLIC_KEY:
            curve_oid = from_pyasn1(EllipticCurveOID, params['namedCurve'])
            Suites = [Suite for Suite in Suites if Suite.curve_oid == curve_oid]
        return Suites


class RsaPkcs1Sha256Mixin:
    iana_id = SignatureScheme.rsa_pkcs1_sha256
    sign_oid = SignatureAlgorithmOID.RSA_WITH_SHA256
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    curve_oid = None
    digest_name = HashOID.sha256
    padding_name = 'EMSA-PKCS1-v1_5'

class RsaPkcs1Sha384Mixin:
    iana_id = SignatureScheme.rsa_pkcs1_sha384
    sign_oid = SignatureAlgorithmOID.RSA_WITH_SHA384
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    curve_oid = None
    digest_name = HashOID.sha384
    padding_name = 'EMSA-PKCS1-v1_5'

class RsaPkcs1Sha512Mixin:
    iana_id = SignatureScheme.rsa_pkcs1_sha512
    sign_oid = SignatureAlgorithmOID.RSA_WITH_SHA512
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    curve_oid = None
    digest_name = HashOID.sha512
    padding_name = 'EMSA-PKCS1-v1_5'

class RsaPssRsaeSha256Mixin:
    iana_id = SignatureScheme.rsa_pss_rsae_sha256
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    curve_oid = None
    digest_name = HashOID.sha256
    padding_name = 'EMSA-PSS'

class RsaPssRsaeSha384Mixin:
    iana_id = SignatureScheme.rsa_pss_rsae_sha384
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    curve_oid = None
    digest_name = HashOID.sha384
    padding_name = 'EMSA-PSS'

class RsaPssRsaeSha512Mixin:
    iana_id = SignatureScheme.rsa_pss_rsae_sha512
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    curve_oid = None
    digest_name = HashOID.sha512
    padding_name = 'EMSA-PSS'

class RsaPssPssSha256Mixin:
    iana_id = SignatureScheme.rsa_pss_pss_sha256
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    pubkey_oid = PublicKeyAlgorithmOID.RSASSA_PSS
    curve_oid = None
    digest_name = HashOID.sha256
    padding_name = 'EMSA-PSS'

class RsaPssPssSha384Mixin:
    iana_id = SignatureScheme.rsa_pss_pss_sha384
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    pubkey_oid = PublicKeyAlgorithmOID.RSASSA_PSS
    curve_oid = None
    digest_name = HashOID.sha384
    padding_name = 'EMSA-PSS'

class RsaPssPssSha512Mixin:
    iana_id = SignatureScheme.rsa_pss_pss_sha512
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    pubkey_oid = PublicKeyAlgorithmOID.RSASSA_PSS
    curve_oid = None
    digest_name = HashOID.sha512
    padding_name = 'EMSA-PSS'


class EcdsaSecp256r1Sha256Mixin:
    iana_id = SignatureScheme.ecdsa_secp256r1_sha256
    sign_oid = SignatureAlgorithmOID.ECDSA_WITH_SHA256
    pubkey_oid = PublicKeyAlgorithmOID.EC_PUBLIC_KEY
    curve_oid = EllipticCurveOID.secp256r1
    digest_name = HashOID.sha256
    padding_name = None

class EcdsaSecp384r1Sha384Mixin:
    iana_id = SignatureScheme.ecdsa_secp384r1_sha384
    sign_oid = SignatureAlgorithmOID.ECDSA_WITH_SHA384
    pubkey_oid = PublicKeyAlgorithmOID.EC_PUBLIC_KEY
    curve_oid = EllipticCurveOID.secp384r1
    digest_name = HashOID.sha384
    padding_name = None

class EcdsaSecp521r1Sha512Mixin:
    iana_id = SignatureScheme.ecdsa_secp521r1_sha512
    sign_oid = SignatureAlgorithmOID.ECDSA_WITH_SHA512
    pubkey_oid = PublicKeyAlgorithmOID.EC_PUBLIC_KEY
    curve_oid = EllipticCurveOID.secp521r1
    digest_name = HashOID.sha512
    padding_name = None


class Ed25519Mixin:
    iana_id = SignatureScheme.ed25519
    sign_oid = SignatureAlgorithmOID.ED25519
    pubkey_oid = PublicKeyAlgorithmOID.ED25519
    curve_oid = None
    digest_name = None
    padding_name = None

class Ed448Mixin:
    iana_id = SignatureScheme.ed448
    sign_oid = SignatureAlgorithmOID.ED448
    pubkey_oid = PublicKeyAlgorithmOID.ED448
    curve_oid = None
    digest_name = None
    padding_name = None
