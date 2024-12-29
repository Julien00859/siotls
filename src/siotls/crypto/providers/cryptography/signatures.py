from collections import defaultdict
from typing import Any, ClassVar

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from siotls.crypto.signatures import (
    EcdsaSecp256r1Sha256Mixin,
    EcdsaSecp384r1Sha384Mixin,
    EcdsaSecp521r1Sha512Mixin,
    Ed448Mixin,
    Ed25519Mixin,
    ISign,
    RsaPkcs1Sha256Mixin,
    RsaPkcs1Sha384Mixin,
    RsaPkcs1Sha512Mixin,
    RsaPssPssSha256Mixin,
    RsaPssPssSha384Mixin,
    RsaPssPssSha512Mixin,
    RsaPssRsaeSha256Mixin,
    RsaPssRsaeSha384Mixin,
    RsaPssRsaeSha512Mixin,
    TLSSignatureSuite,
)
from x509oid import PublicKeyAlgorithmOID


class _RSAMixin:
    pubkey_oid_index: ClassVar = defaultdict(tuple)

    pubkey_oid: PublicKeyAlgorithmOID
    digestmod: hashes.Hash
    padding: Any

    def __init_subclass__(cls, *, register=True, **kwargs):
        super().__init_subclass__(**kwargs)
        if register and _RSAMixin in cls.__bases__:
            cls.pubkey_oid_index[None] += (cls,)
            cls.pubkey_oid_index[cls.pubkey_oid] += (cls,)

    def sign(self, message):
        return self.key.sign(message, self.padding, self.digestmod)

    def verify(self, signature, message):
        self.key.verify(signature, message, self.padding, self.digestmod)

class RsaPkcs1Sha256(RsaPkcs1Sha256Mixin, _RSAMixin, ISign, TLSSignatureSuite):
    digestmod = hashes.SHA256()
    padding = padding.PKCS1v15()

class RsaPkcs1Sha384(RsaPkcs1Sha384Mixin, _RSAMixin, ISign, TLSSignatureSuite):
    digestmod = hashes.SHA384()
    padding = padding.PKCS1v15()

class RsaPkcs1Sha512(RsaPkcs1Sha512Mixin, _RSAMixin, ISign, TLSSignatureSuite):
    digestmod = hashes.SHA512()
    padding = padding.PKCS1v15()

class RsaPssRsaeSha256(RsaPssRsaeSha256Mixin, _RSAMixin, ISign, TLSSignatureSuite):
    digestmod = hashes.SHA256()
    padding = padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.DIGEST_LENGTH)

class RsaPssRsaeSha384(RsaPssRsaeSha384Mixin, _RSAMixin, ISign, TLSSignatureSuite):
    digestmod = hashes.SHA384()
    padding = padding.PSS(padding.MGF1(hashes.SHA384()), padding.PSS.DIGEST_LENGTH)

class RsaPssRsaeSha512(RsaPssRsaeSha512Mixin, _RSAMixin, ISign, TLSSignatureSuite):
    digestmod = hashes.SHA512()
    padding = padding.PSS(padding.MGF1(hashes.SHA512()), padding.PSS.DIGEST_LENGTH)

class RsaPssPssSha256(RsaPssPssSha256Mixin, _RSAMixin, ISign, TLSSignatureSuite):
    digestmod = hashes.SHA256()
    padding = padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.DIGEST_LENGTH)

class RsaPssPssSha384(RsaPssPssSha384Mixin, _RSAMixin, ISign, TLSSignatureSuite):
    digestmod = hashes.SHA384()
    padding = padding.PSS(padding.MGF1(hashes.SHA384()), padding.PSS.DIGEST_LENGTH)

class RsaPssPssSha512(RsaPssPssSha512Mixin, _RSAMixin, ISign, TLSSignatureSuite):
    digestmod = hashes.SHA512()
    padding = padding.PSS(padding.MGF1(hashes.SHA512()), padding.PSS.DIGEST_LENGTH)


class _ECDSAMixin:
    curve_name_index: ClassVar = {}

    digestmod: hashes.Hash
    curve_name: str

    def __init_subclass__(cls, *, register=True, **kwargs):
        super().__init_subclass__(**kwargs)
        if register and _ECDSAMixin in cls.__bases__:
            cls.curve_name_index[cls.curve_name] = cls

    def sign(self, message):
        return self.key.sign(message, ec.ECDSA(self.digestmod))

    def verify(self, signature, message):
        self.key.verify(signature, message, ec.ECDSA(self.digestmod))

class EcdsaSecp256r1Sha256(EcdsaSecp256r1Sha256Mixin, _ECDSAMixin, ISign, TLSSignatureSuite):
    digestmod = hashes.SHA256()
    curve_name = ec.SECP256R1.name

class EcdsaSecp384r1Sha384(EcdsaSecp384r1Sha384Mixin, _ECDSAMixin, ISign, TLSSignatureSuite):
    digestmod = hashes.SHA384()
    curve_name = ec.SECP384R1.name

class EcdsaSecp521r1Sha512(EcdsaSecp521r1Sha512Mixin, _ECDSAMixin, ISign, TLSSignatureSuite):
    digestmod = hashes.SHA512()
    curve_name = ec.SECP521R1.name


class _EDMixin:
    def sign(self, message):
        return self.key.sign(message)

    def verify(self, signature, message):
        self.key.verify(signature, message)

class Ed25519(Ed25519Mixin, _EDMixin, ISign, TLSSignatureSuite):
    pass

class Ed448(Ed448Mixin, _EDMixin, ISign, TLSSignatureSuite):
    pass
