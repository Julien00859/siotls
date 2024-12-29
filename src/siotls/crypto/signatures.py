# class names
# ruff: noqa: N801
import abc
from typing import Any, ClassVar, Literal

from siotls.iana import SignatureScheme
from siotls.utils import RegistryMeta
from x509oid import EllipticCurveOID, PublicKeyAlgorithmOID, SignatureAlgorithmOID


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

    iana_id: SignatureScheme
    sign_oid: SignatureAlgorithmOID
    pubkey_id: PublicKeyAlgorithmOID
    curve_oid: EllipticCurveOID | None
    digest_name: Literal['sha256', 'sha384', 'sha512'] | None
    padding_name: Literal['pkcs1', 'pss'] | None
    _key: Any

    def __init_subclass__(cls, *, register=True, **kwargs):
        super().__init_subclass__(**kwargs)
        if register and TLSSignatureSuite in cls.__bases__:
            cls._signature_iana_registry[cls.iana_id] = cls

    def __init__(self, key):
        self._key = key

    @classmethod
    def for_signature(cls, certificate, sign_oid, digest_name, parameters=None):
        # It is for verifying EXISTING signatures.
        signs = cls.for_certificate(certificate)
        if issubclass(signs[0], _RSAMixin):
            signs = [
                sign for sign in signs
                if sign.sign_oid == sign_oid
                if sign.digest_name == digest_name
                if parameters is None or sign.padding.name == parameters.name
            ]
        elif issubclass(signs[0], _ECDSAMixin):
            signs = [
                sign for sign in signs
                if sign.sign_oid == sign_oid
                if sign.digest_name == digest_name
            ]

        if len(signs) == 0:
            e = "no matching algorithm"
            raise ValueError(e)
        elif len(signs) > 1:
            e = "multiple matching algorithms"
            raise ValueError(e)
        if sign_oid and signs[0].sign_oid != sign_oid:
            e = "signature algorithm don't match"
            raise ValueError(e)
        return signs[0]

    @classmethod
    def for_certificate(cls, certificate):
        # It is for signing NEW messages. DO NOT use this one with
        # ExtensionType.SIGNATURE_ALGORITHMS_CERT
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
    padding_name = 'pkcs1'

class RsaPkcs1Sha384Mixin:
    iana_id = SignatureScheme.rsa_pkcs1_sha384
    sign_oid = SignatureAlgorithmOID.RSA_WITH_SHA384
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    curve_oid = None
    digest_name = 'sha384'
    padding_name = 'pkcs1'

class RsaPkcs1Sha512Mixin:
    iana_id = SignatureScheme.rsa_pkcs1_sha512
    sign_oid = SignatureAlgorithmOID.RSA_WITH_SHA512
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    curve_oid = None
    digest_name = 'sha512'
    padding_name = 'pkcs1'

class RsaPssRsaeSha256Mixin:
    iana_id = SignatureScheme.rsa_pss_rsae_sha256
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    curve_oid = None
    digest_name = 'sha256'
    padding_name = 'pss'

class RsaPssRsaeSha384Mixin:
    iana_id = SignatureScheme.rsa_pss_rsae_sha384
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    curve_oid = None
    digest_name = 'sha384'
    padding_name = 'pss'

class RsaPssRsaeSha512Mixin:
    iana_id = SignatureScheme.rsa_pss_rsae_sha512
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    curve_oid = None
    digest_name = 'sha512'
    padding_name = 'pss'

class RsaPssPssSha256Mixin:
    iana_id = SignatureScheme.rsa_pss_pss_sha256
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    pubkey_oid = PublicKeyAlgorithmOID.RSASSA_PSS
    curve_oid = None
    digest_name = 'sha256'
    padding_name = 'pss'

class RsaPssPssSha384Mixin:
    iana_id = SignatureScheme.rsa_pss_pss_sha384
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    pubkey_oid = PublicKeyAlgorithmOID.RSASSA_PSS
    curve_oid = None
    digest_name = 'sha384'
    padding_name = 'pss'

class RsaPssPssSha512Mixin:
    iana_id = SignatureScheme.rsa_pss_pss_sha512
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    pubkey_oid = PublicKeyAlgorithmOID.RSASSA_PSS
    digest_name = 'sha512'
    padding_name = 'pss'

class EcdsaSecp256r1Sha256Mixin:
    iana_id = SignatureScheme.ecdsa_secp256r1_sha256
    sign_oid = SignatureAlgorithmOID.ECDSA_WITH_SHA256
    pubkey_oid = PublicKeyAlgorithmOID.EC_PUBLIC_KEY
    curve_oid = EllipticCurveOID.SECP256R1
    digest_name = 'sha256'
    padding_name = None


class EcdsaSecp384r1Sha384Mixin:
    iana_id = SignatureScheme.ecdsa_secp384r1_sha384
    sign_oid = SignatureAlgorithmOID.ECDSA_WITH_SHA384
    pubkey_oid = PublicKeyAlgorithmOID.EC_PUBLIC_KEY
    curve_oid = EllipticCurveOID.SECP384R1
    digest_name = 'sha384'
    padding_name = None

class EcdsaSecp521r1Sha512Mixin:
    iana_id = SignatureScheme.ecdsa_secp521r1_sha512
    sign_oid = SignatureAlgorithmOID.ECDSA_WITH_SHA512
    pubkey_oid = PublicKeyAlgorithmOID.EC_PUBLIC_KEY
    curve_oid = EllipticCurveOID.SECP521R1
    digest_name = 'sha512'
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
