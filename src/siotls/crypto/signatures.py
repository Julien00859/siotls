# class names
# ruff: noqa: N801
from collections import defaultdict

from cryptography.hazmat._oid import PublicKeyAlgorithmOID, SignatureAlgorithmOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes

from siotls.iana import SignatureScheme

signature_suite_registry = {}
_oid_registry = defaultdict(dict)

class TLSSignatureSuite:
    iana_id: SignatureScheme
    pubkey_oid: PublicKeyAlgorithmOID
    sign_oid: SignatureAlgorithmOID

    key: PublicKeyTypes | PrivateKeyTypes

    def __init__(self, key):
        self.key = key

    def sign(self, message):
        raise NotImplementedError("abstract method")  # noqa: EM101

    def verify(self, signature, message):
        raise NotImplementedError("abstract method")  # noqa: EM101

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if TLSSignatureSuite in cls.__bases__:
            signature_suite_registry[cls.iana_id] = cls
            _oid_registry[cls.pubkey_oid][cls.sign_oid][getattr(cls, 'digestmod', None)] = cls

    @staticmethod
    def for_cert(cert):
        return (
            _oid_registry
            [cert.public_key_algorithm_oid]
            [cert.signature_algorithm_oid]
            [cert.signature_hash_algorithm]
        )

    @staticmethod
    def for_public_key(public_key):
        match public_key:
            case RSAPublicKey():
                return {
                    TLS_RSA_PKCS1_SHA256,
                    TLS_RSA_PKCS1_SHA384,
                    TLS_RSA_PKCS1_SHA512,
                    TLS_RSA_PSS_PSS_SHA256,
                    TLS_RSA_PSS_PSS_SHA384,
                    TLS_RSA_PSS_PSS_SHA512,
                    TLS_RSA_PSS_RSAE_SHA256,
                    TLS_RSA_PSS_RSAE_SHA384,
                    TLS_RSA_PSS_RSAE_SHA512,
                }
            case EllipticCurvePublicKey():
                return {
                    TLS_ECDSA_SECP256R1_SHA256,
                    TLS_ECDSA_SECP384R1_SHA384,
                    TLS_ECDSA_SECP521R1_SHA512,
                }
            case Ed25519PublicKey():
                return {TLS_ED25519}
            case Ed448PublicKey():
                return {TLS_ED448}


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
    padding = padding.PSS(padding.MGF1(hashes.SHA256, padding.PSS.MAX_LENGTH))

class TLS_RSA_PSS_RSAE_SHA384(_RSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.rsa_pss_rsae_sha384
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    digestmod = hashes.SHA384()
    padding = padding.PSS(padding.MGF1(hashes.SHA384, padding.PSS.MAX_LENGTH))

class TLS_RSA_PSS_RSAE_SHA512(_RSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.rsa_pss_rsae_sha512
    pubkey_oid = PublicKeyAlgorithmOID.RSAES_PKCS1_v1_5
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    digestmod = hashes.SHA512()
    padding = padding.PSS(padding.MGF1(hashes.SHA512, padding.PSS.MAX_LENGTH))

class TLS_RSA_PSS_PSS_SHA256(_RSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.rsa_pss_pss_sha256
    pubkey_oid = PublicKeyAlgorithmOID.RSASSA_PSS
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    digestmod = hashes.SHA256()
    padding = padding.PSS(padding.MGF1(hashes.SHA256, padding.PSS.MAX_LENGTH))

class TLS_RSA_PSS_PSS_SHA384(_RSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.rsa_pss_pss_sha384
    pubkey_oid = PublicKeyAlgorithmOID.RSASSA_PSS
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    digestmod = hashes.SHA384()
    padding = padding.PSS(padding.MGF1(hashes.SHA384, padding.PSS.MAX_LENGTH))

class TLS_RSA_PSS_PSS_SHA512(_RSAMixin, TLSSignatureSuite):
    iana_id = SignatureScheme.rsa_pss_pss_sha512
    pubkey_oid = PublicKeyAlgorithmOID.RSASSA_PSS
    sign_oid = SignatureAlgorithmOID.RSASSA_PSS
    digestmod = hashes.SHA512()
    padding = padding.PSS(padding.MGF1(hashes.SHA512, padding.PSS.MAX_LENGTH))


class _ECDSAMixin:
    digestmod: hashes.Hash

    def sign(self, message):
        return self.key.sign(message, self.digestmod)

    def verify(self, signature, message):
        self.key.verify(signature, message, ECDSA(self.digestmod))

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
