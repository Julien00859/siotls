# class names
# ruff: noqa: N801
from abc import abstractmethod
from typing import ClassVar

from cryptography.hazmat._oid import PublicKeyAlgorithmOID, SignatureAlgorithmOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, types

from siotls.iana import SignatureScheme
from siotls.utils import RegistryMeta


class TLSSignatureSuite(metaclass=RegistryMeta):
    _pubkey_registry: ClassVar = {}
    _registry: ClassVar = {}
    _sign_registry: ClassVar = {}

    iana_id: SignatureScheme
    pubkey_oid: PublicKeyAlgorithmOID
    sign_oid: SignatureAlgorithmOID

    key: types.PublicKeyTypes | types.PrivateKeyTypes

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if TLSSignatureSuite not in cls.__bases__:
            return
        cls._pubkey_registry.setdefault(cls.pubkey_oid, {})[cls.iana_id] = cls
        cls._registry[cls.iana_id] = cls
        cls._sign_registry[cls.sign_oid] = cls

    @classmethod
    def from_signature_oid(cls, signature_oid):
        return cls._sign_registry[signature_oid]

    @classmethod
    def for_public_key_oid(cls, public_key_oid):
        return cls._pubkey_registry[public_key_oid]

    def __init__(self, key):
        self.key = key

    @abstractmethod
    def sign(self, message):
        raise NotImplementedError

    @abstractmethod
    def verify(self, signature, message):
        raise NotImplementedError


class _RSAMixin:
    digestmod: hashes.Hash
    padding = padding.PKCS1v15()

    def sign(self, message):
        return self.key.sign(message, self.padding, self.digestmod)

    def verify(self, signature, message):
        self.key.verify(signature, message, self.padding, self.digestmod)

class TLS_RSA_PKCS1_SHA256(_RSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.rsa_pkcs1_sha256
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    sign_oid = SignatureAlgorithmOID.RSA_WITH_SHA256
    digestmod = hashes.SHA256()

class TLS_RSA_PKCS1_SHA384(_RSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.rsa_pkcs1_sha384
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    sign_oid = SignatureAlgorithmOID.RSA_WITH_SHA384
    digestmod = hashes.SHA384()

class TLS_RSA_PKCS1_SHA512(_RSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.rsa_pkcs1_sha512
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    sign_oid = SignatureAlgorithmOID.RSA_WITH_SHA512
    digestmod = hashes.SHA512()

class TLS_RSA_PSS_RSAE_SHA256(_RSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.rsa_pss_rsae_sha256
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    digestmod = hashes.SHA256()
    padding = padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.DIGEST_LENGTH)

class TLS_RSA_PSS_RSAE_SHA384(_RSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.rsa_pss_rsae_sha384
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    digestmod = hashes.SHA384()
    padding = padding.PSS(padding.MGF1(hashes.SHA384()), padding.PSS.DIGEST_LENGTH)

class TLS_RSA_PSS_RSAE_SHA512(_RSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.rsa_pss_rsae_sha512
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    digestmod = hashes.SHA512()
    padding = padding.PSS(padding.MGF1(hashes.SHA512()), padding.PSS.DIGEST_LENGTH)

class TLS_RSA_PSS_PSS_SHA256(_RSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.rsa_pss_pss_sha256
    pubkey_oid = PublicKeyAlgorithmOID.RSASSA_PSS
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    digestmod = hashes.SHA256()
    padding = padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.DIGEST_LENGTH)

class TLS_RSA_PSS_PSS_SHA384(_RSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.rsa_pss_pss_sha384
    pubkey_oid = PublicKeyAlgorithmOID.RSASSA_PSS
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    digestmod = hashes.SHA384()
    padding = padding.PSS(padding.MGF1(hashes.SHA384()), padding.PSS.DIGEST_LENGTH)

class TLS_RSA_PSS_PSS_SHA512(_RSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.rsa_pss_pss_sha512
    pubkey_oid = PublicKeyAlgorithmOID.RSASSA_PSS
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    digestmod = hashes.SHA512()
    padding = padding.PSS(padding.MGF1(hashes.SHA512()), padding.PSS.DIGEST_LENGTH)


class _ECDSAMixin:
    digestmod: hashes.Hash

    def sign(self, message):
        return self.key.sign(message, ec.ECDSA(self.digestmod))

    def verify(self, signature, message):
        self.key.verify(signature, message, ec.ECDSA(self.digestmod))

class TLS_ECDSA_SECP256R1_SHA256(_ECDSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.ecdsa_secp256r1_sha256
    pubkey_oid = PublicKeyAlgorithmOID.EC_PUBLIC_KEY
    sign_oid = SignatureAlgorithmOID.ECDSA_WITH_SHA256
    digestmod = hashes.SHA256()

class TLS_ECDSA_SECP384R1_SHA384(_ECDSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.ecdsa_secp384r1_sha384
    pubkey_oid = PublicKeyAlgorithmOID.EC_PUBLIC_KEY
    sign_oid = SignatureAlgorithmOID.ECDSA_WITH_SHA384
    digestmod = hashes.SHA384()

class TLS_ECDSA_SECP521R1_SHA512(_ECDSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.ecdsa_secp521r1_sha512
    pubkey_oid = PublicKeyAlgorithmOID.EC_PUBLIC_KEY
    sign_oid = SignatureAlgorithmOID.ECDSA_WITH_SHA512
    digestmod = hashes.SHA512()


class _EDMixin:
    def sign(self, message):
        return self.key.sign(message)

    def verify(self, signature, message):
        self.key.verify(signature, message)

class TLS_ED25519(_EDMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.ed25519
    pubkey_oid = PublicKeyAlgorithmOID.ED25519
    sign_oid = SignatureAlgorithmOID.ED25519

class TLS_ED448(_EDMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.ed448
    pubkey_oid = PublicKeyAlgorithmOID.ED448
    sign_oid = SignatureAlgorithmOID.ED448
