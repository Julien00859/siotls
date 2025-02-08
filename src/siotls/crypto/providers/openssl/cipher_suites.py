import functools

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import aead

from siotls.contents import alerts
from siotls.crypto.cipher_suites import (
    Aes128Ccm8Mixin,
    Aes128CcmMixin,
    Aes128GcmMixin,
    Aes256GcmMixin,
    ChaPolyMixin,
    TLSCipherSuite,
)


class _CipherMixin:
    def _decrypt(self, nonce, data, associated_data):
        try:
            return self._read_cipher.decrypt(nonce, data, associated_data)
        except InvalidTag as exc:
            raise alerts.DecryptError from exc

    def _encrypt(self, nonce, data, associated_data):
        return self._write_cipher.encrypt(nonce, data, associated_data)


class Aes128Gcm(Aes128GcmMixin, _CipherMixin, TLSCipherSuite):
    _ciphermod = aead.AESGCM

class Aes256Gcm(Aes256GcmMixin, _CipherMixin, TLSCipherSuite):
    _ciphermod = aead.AESGCM

class ChaPoly(ChaPolyMixin, _CipherMixin, TLSCipherSuite):
    _ciphermod = aead.ChaCha20Poly1305

class Aes128Ccm(Aes128CcmMixin, _CipherMixin, TLSCipherSuite):
    _ciphermod = aead.AESCCM

class Aes128Ccm8(Aes128Ccm8Mixin, _CipherMixin, TLSCipherSuite):
    _ciphermod = functools.partial(aead.AESCCM, tag_length=8)
