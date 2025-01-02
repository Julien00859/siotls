from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
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


class _RSAMixin(ISign):
    digestmod: hashes.Hash
    padding: padding.PKCS1v15 | padding.PSS

    def sign(self, message):
        return self._key.sign(message, self.padding, self.digestmod)

    def verify(self, signature, message):
        self._key.verify(signature, message, self.padding, self.digestmod)

class RsaPkcs1Sha256(RsaPkcs1Sha256Mixin, _RSAMixin, TLSSignatureSuite):
    digestmod = hashes.SHA256()
    padding = padding.PKCS1v15()

class RsaPkcs1Sha384(RsaPkcs1Sha384Mixin, _RSAMixin, TLSSignatureSuite):
    digestmod = hashes.SHA384()
    padding = padding.PKCS1v15()

class RsaPkcs1Sha512(RsaPkcs1Sha512Mixin, _RSAMixin, TLSSignatureSuite):
    digestmod = hashes.SHA512()
    padding = padding.PKCS1v15()

class RsaPssRsaeSha256(RsaPssRsaeSha256Mixin, _RSAMixin, TLSSignatureSuite):
    digestmod = hashes.SHA256()
    padding = padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.DIGEST_LENGTH)

class RsaPssRsaeSha384(RsaPssRsaeSha384Mixin, _RSAMixin, TLSSignatureSuite):
    digestmod = hashes.SHA384()
    padding = padding.PSS(padding.MGF1(hashes.SHA384()), padding.PSS.DIGEST_LENGTH)

class RsaPssRsaeSha512(RsaPssRsaeSha512Mixin, _RSAMixin, TLSSignatureSuite):
    digestmod = hashes.SHA512()
    padding = padding.PSS(padding.MGF1(hashes.SHA512()), padding.PSS.DIGEST_LENGTH)

class RsaPssPssSha256(RsaPssPssSha256Mixin, _RSAMixin, TLSSignatureSuite):
    digestmod = hashes.SHA256()
    padding = padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.DIGEST_LENGTH)

class RsaPssPssSha384(RsaPssPssSha384Mixin, _RSAMixin, TLSSignatureSuite):
    digestmod = hashes.SHA384()
    padding = padding.PSS(padding.MGF1(hashes.SHA384()), padding.PSS.DIGEST_LENGTH)

class RsaPssPssSha512(RsaPssPssSha512Mixin, _RSAMixin, TLSSignatureSuite):
    digestmod = hashes.SHA512()
    padding = padding.PSS(padding.MGF1(hashes.SHA512()), padding.PSS.DIGEST_LENGTH)


class _ECDSAMixin:
    digestmod: hashes.Hash

    def sign(self, message):
        return self._key.sign(message, ec.ECDSA(self.digestmod))

    def verify(self, signature, message):
        self._key.verify(signature, message, ec.ECDSA(self.digestmod))

class EcdsaSecp256r1Sha256(EcdsaSecp256r1Sha256Mixin, _ECDSAMixin, TLSSignatureSuite):
    digestmod = hashes.SHA256()

class EcdsaSecp384r1Sha384(EcdsaSecp384r1Sha384Mixin, _ECDSAMixin, TLSSignatureSuite):
    digestmod = hashes.SHA384()

class EcdsaSecp521r1Sha512(EcdsaSecp521r1Sha512Mixin, _ECDSAMixin, TLSSignatureSuite):
    digestmod = hashes.SHA512()


class _EDMixin:
    def sign(self, message):
        return self._key.sign(message)

    def verify(self, signature, message):
        self._key.verify(signature, message)

class Ed25519(Ed25519Mixin, _EDMixin, TLSSignatureSuite):
    pass

class Ed448(Ed448Mixin, _EDMixin, TLSSignatureSuite):
    pass
