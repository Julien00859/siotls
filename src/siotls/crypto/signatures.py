# class names
# ruff: noqa: N801
from abc import abstractmethod
from collections import defaultdict
from typing import Any, ClassVar

from cryptography.hazmat._oid import PublicKeyAlgorithmOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa, types

from siotls.iana import SignatureScheme
from siotls.utils import RegistryMeta


class TLSSignatureSuite(metaclass=RegistryMeta):
    _registry: ClassVar = {}

    iana_id: SignatureScheme
    key: types.PublicKeyTypes | types.PrivateKeyTypes

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if TLSSignatureSuite not in cls.__bases__:
            return
        cls._registry[cls.iana_id] = cls

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
                return (TLS_ED25519,)
            case ed448.Ed448PublicKey() | ed448.Ed448PrivateKey():
                return (TLS_ED448,)

        e = f"unknown key: {key!r}"
        raise ValueError(e)



    def __init__(self, key):
        self.key = key

    @abstractmethod
    def sign(self, message):
        raise NotImplementedError

    @abstractmethod
    def verify(self, signature, message):
        raise NotImplementedError


class _RSAMixin:
    pubkey_oid_index: ClassVar = defaultdict(tuple)

    pubkey_oid: PublicKeyAlgorithmOID
    digestmod: hashes.Hash
    padding: Any

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if _RSAMixin not in cls.__bases__:
            return
        cls.pubkey_oid_index[None] += (cls,)
        cls.pubkey_oid_index[cls.pubkey_oid] += (cls,)

    def sign(self, message):
        return self.key.sign(message, self.padding, self.digestmod)

    def verify(self, signature, message):
        self.key.verify(signature, message, self.padding, self.digestmod)

class TLS_RSA_PKCS1_SHA256(_RSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.rsa_pkcs1_sha256
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    digestmod = hashes.SHA256()
    padding = padding.PKCS1v15()

class TLS_RSA_PKCS1_SHA384(_RSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.rsa_pkcs1_sha384
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    digestmod = hashes.SHA384()
    padding = padding.PKCS1v15()

class TLS_RSA_PKCS1_SHA512(_RSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.rsa_pkcs1_sha512
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    digestmod = hashes.SHA512()
    padding = padding.PKCS1v15()

class TLS_RSA_PSS_RSAE_SHA256(_RSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.rsa_pss_rsae_sha256
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    digestmod = hashes.SHA256()
    padding = padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.DIGEST_LENGTH)

class TLS_RSA_PSS_RSAE_SHA384(_RSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.rsa_pss_rsae_sha384
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    digestmod = hashes.SHA384()
    padding = padding.PSS(padding.MGF1(hashes.SHA384()), padding.PSS.DIGEST_LENGTH)

class TLS_RSA_PSS_RSAE_SHA512(_RSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.rsa_pss_rsae_sha512
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    digestmod = hashes.SHA512()
    padding = padding.PSS(padding.MGF1(hashes.SHA512()), padding.PSS.DIGEST_LENGTH)

class TLS_RSA_PSS_PSS_SHA256(_RSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.rsa_pss_pss_sha256
    pubkey_oid = PublicKeyAlgorithmOID.RSASSA_PSS
    digestmod = hashes.SHA256()
    padding = padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.DIGEST_LENGTH)

class TLS_RSA_PSS_PSS_SHA384(_RSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.rsa_pss_pss_sha384
    pubkey_oid = PublicKeyAlgorithmOID.RSASSA_PSS
    digestmod = hashes.SHA384()
    padding = padding.PSS(padding.MGF1(hashes.SHA384()), padding.PSS.DIGEST_LENGTH)

class TLS_RSA_PSS_PSS_SHA512(_RSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.rsa_pss_pss_sha512
    pubkey_oid = PublicKeyAlgorithmOID.RSASSA_PSS
    digestmod = hashes.SHA512()
    padding = padding.PSS(padding.MGF1(hashes.SHA512()), padding.PSS.DIGEST_LENGTH)


class _ECDSAMixin:
    curve_name_index: ClassVar = {}
    digestmod: hashes.Hash
    curve_name: str

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if _ECDSAMixin not in cls.__bases__:
            return
        cls.curve_name_index[cls.curve_name] = cls

    def sign(self, message):
        return self.key.sign(message, ec.ECDSA(self.digestmod))

    def verify(self, signature, message):
        self.key.verify(signature, message, ec.ECDSA(self.digestmod))

class TLS_ECDSA_SECP256R1_SHA256(_ECDSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.ecdsa_secp256r1_sha256
    digestmod = hashes.SHA256()
    curve_name = ec.SECP256R1.name

class TLS_ECDSA_SECP384R1_SHA384(_ECDSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.ecdsa_secp384r1_sha384
    digestmod = hashes.SHA384()
    curve_name = ec.SECP384R1.name

class TLS_ECDSA_SECP521R1_SHA512(_ECDSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.ecdsa_secp521r1_sha512
    digestmod = hashes.SHA512()
    curve_name = ec.SECP521R1.name


class _EDMixin:
    def sign(self, message):
        return self.key.sign(message)

    def verify(self, signature, message):
        self.key.verify(signature, message)

class TLS_ED25519(_EDMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.ed25519

class TLS_ED448(_EDMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.ed448
