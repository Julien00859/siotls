# class names
# ruff: noqa: N801
import abc
from typing import Any, ClassVar, Literal

from siotls.iana import SignatureScheme
from siotls.utils import RegistryMeta
from x509oid import EllipticCurveOID, PublicKeyAlgorithmOID, SignatureAlgorithmOID

DIGEST_NAME = Literal['sha256', 'sha384', 'sha512']
PARAMETERS_NAME = Literal['EMSA-PKCS1-v1_5', 'EMSA-PSS']


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

    iana_id: SignatureScheme
    sign_oid: SignatureAlgorithmOID
    pubkey_id: PublicKeyAlgorithmOID
    curve_oid: EllipticCurveOID | None
    digest_name: DIGEST_NAME | None
    parameters_name: PARAMETERS_NAME | None
    _key: Any

    def __init_subclass__(cls, *, register=True, **kwargs):
        super().__init_subclass__(**kwargs)
        if register and TLSSignatureSuite in cls.__bases__:
            cls._signature_iana_registry[cls.iana_id] = cls
            cls._signature_algo_registry[(
                cls.sign_oid,
                cls.curve_oid,
                cls.digest_name,
                cls.parameters_name
            )] = cls

    def __init__(self, key):
        self._key = key

    @classmethod
    def for_signature(
        cls,
        sign_oid: SignatureAlgorithmOID,
        curve_oid: EllipticCurveOID | None = None,
        digest_name: DIGEST_NAME | None = None,
        parameters_name: PARAMETERS_NAME | None = None,
    ):
        # It is for verifying EXISTING signatures.
        return cls._signature_algo_registry[(sign_oid, curve_oid, digest_name, parameters_name)]

    @classmethod
    def for_certificate(cls, certificate):
        # It is for signing NEW messages. DO NOT use this one with
        # ExtensionType.SIGNATURE_ALGORITHMS_CERT
        # This is a more selective version of for_key because RSA-PSS
        # means the key MUST be used with PSS padding. So even if
        # technically the key could be used with pkc1
        return cls.for_key(
            certificate.public_key(),
            certificate.public_key_algorithm_oid,
        )

    @classmethod
    def for_key(cls, key, pubkey_oid=None):
        match key:
            case rsa.RSAPublicKey() | rsa.RSAPrivateKey():
                try:
                    return _RSAMixin.pubkey_oid_index[pubkey_oid]
                except KeyError as exc:
                    e = f"unknown RSA public key OID: {pubkey_oid}"
                    raise ValueError(e) from exc
            case ec.EllipticCurvePublicKey() | ec.EllipticCurvePrivateKey():
                try:
                    return (_ECDSAMixin.curve_name_index[key.curve.name],)
                except KeyError as exc:
                    e = f"unknown ECDSA curve: {key.curve.name}"
                    raise ValueError(e) from exc
            case ed25519.Ed25519PublicKey() | ed25519.Ed25519PrivateKey():
                return (cls[SignatureScheme.ed25519],)
            case ed448.Ed448PublicKey() | ed448.Ed448PrivateKey():
                return (cls[SignatureScheme.ed448],)

        e = f"unknown key: {key!r}"
        raise ValueError(e)


class RsaPkcs1Sha256Mixin:
    iana_id = SignatureScheme.rsa_pkcs1_sha256
    sign_oid = SignatureAlgorithmOID.RSA_WITH_SHA256
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    curve_oid = None
    digest_name = 'sha256'
    parameters_name = 'EMSA-PKCS1-v1_5'

class RsaPkcs1Sha384Mixin:
    iana_id = SignatureScheme.rsa_pkcs1_sha384
    sign_oid = SignatureAlgorithmOID.RSA_WITH_SHA384
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    curve_oid = None
    digest_name = 'sha384'
    parameters_name = 'EMSA-PKCS1-v1_5'

class RsaPkcs1Sha512Mixin:
    iana_id = SignatureScheme.rsa_pkcs1_sha512
    sign_oid = SignatureAlgorithmOID.RSA_WITH_SHA512
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    curve_oid = None
    digest_name = 'sha512'
    parameters_name = 'EMSA-PKCS1-v1_5'

class RsaPssRsaeSha256Mixin:
    iana_id = SignatureScheme.rsa_pss_rsae_sha256
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    curve_oid = None
    digest_name = 'sha256'
    parameters_name = 'EMSA-PSS'

class RsaPssRsaeSha384Mixin:
    iana_id = SignatureScheme.rsa_pss_rsae_sha384
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    curve_oid = None
    digest_name = 'sha384'
    parameters_name = 'EMSA-PSS'

class RsaPssRsaeSha512Mixin:
    iana_id = SignatureScheme.rsa_pss_rsae_sha512
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    curve_oid = None
    digest_name = 'sha512'
    parameters_name = 'EMSA-PSS'

class RsaPssPssSha256Mixin:
    iana_id = SignatureScheme.rsa_pss_pss_sha256
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    pubkey_oid = PublicKeyAlgorithmOID.RSASSA_PSS
    curve_oid = None
    digest_name = 'sha256'
    parameters_name = 'EMSA-PSS'

class RsaPssPssSha384Mixin:
    iana_id = SignatureScheme.rsa_pss_pss_sha384
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    pubkey_oid = PublicKeyAlgorithmOID.RSASSA_PSS
    curve_oid = None
    digest_name = 'sha384'
    parameters_name = 'EMSA-PSS'

class RsaPssPssSha512Mixin:
    iana_id = SignatureScheme.rsa_pss_pss_sha512
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    pubkey_oid = PublicKeyAlgorithmOID.RSASSA_PSS
    digest_name = 'sha512'
    parameters_name = 'EMSA-PSS'


# >>> obj = der_decode(data, Certificate)[0]
# >>> params = obj['tbsCertificate']['subjectPublicKeyInfo']['algorithm']['parameters']
# >>> x509oid.EllipticCurveOID('.'.join(map(str, der_decode(params)[0])))
# <EllipticCurveOID.secp384r1: '1.3.132.0.34'>
# >>> cert = load_pem_x509_certificate(data)
# >>> x509oid.EllipticCurveOID[cert.public_key().curve.name]
# <EllipticCurveOID.secp384r1: '1.3.132.0.34'>


class EcdsaSecp256r1Sha256Mixin:
    iana_id = SignatureScheme.ecdsa_secp256r1_sha256
    sign_oid = SignatureAlgorithmOID.ECDSA_WITH_SHA256
    pubkey_oid = PublicKeyAlgorithmOID.EC_PUBLIC_KEY
    curve_oid = EllipticCurveOID.SECP256R1
    digest_name = 'sha256'
    parameters_name = None

class EcdsaSecp384r1Sha384Mixin:
    iana_id = SignatureScheme.ecdsa_secp384r1_sha384
    sign_oid = SignatureAlgorithmOID.ECDSA_WITH_SHA384
    pubkey_oid = PublicKeyAlgorithmOID.EC_PUBLIC_KEY
    curve_oid = EllipticCurveOID.SECP384R1
    digest_name = 'sha384'
    parameters_name = None

class EcdsaSecp521r1Sha512Mixin:
    iana_id = SignatureScheme.ecdsa_secp521r1_sha512
    sign_oid = SignatureAlgorithmOID.ECDSA_WITH_SHA512
    pubkey_oid = PublicKeyAlgorithmOID.EC_PUBLIC_KEY
    curve_oid = EllipticCurveOID.SECP521R1
    digest_name = 'sha512'
    parameters_name = None


class Ed25519Mixin:
    iana_id = SignatureScheme.ed25519
    sign_oid = SignatureAlgorithmOID.ED25519
    pubkey_oid = PublicKeyAlgorithmOID.ED25519
    curve_oid = None
    digest_name = None
    parameters_name = None

class Ed448Mixin:
    iana_id = SignatureScheme.ed448
    sign_oid = SignatureAlgorithmOID.ED448
    pubkey_oid = PublicKeyAlgorithmOID.ED448
    curve_oid = None
    digest_name = None
    parameters_name = None
