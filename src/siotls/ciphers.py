import hashlib
from cryptography.hazmat.primitives.ciphers import aead
from siotls.iana import CipherSuites

REKEY_THRESHOLD = 1024  # arbitrary


class _CipherMixin:
    def __init__(self, key, **kwargs):
        if len(key) != self.key_length:
            e = f"Key must be {self.key_length} bytes long"
            raise ValueError(e)
        super().__init__(key, **kwargs)
        self.usage_left = self.usage_limit

    def encrypt(self, nonce, data, associated_data):
        self.usage_left -= 1
        if self.usage_left < 0:
            e = "Key usage exceeded"
            raise RuntimeError(e)
        return super().encrypt(nonce, data, associated_data)

    @property
    def should_rekey(self):
        return self.usage_left < REKEY_THRESHOLD

    @property
    def nonce_length_min(self):
        return self.nonce_length

    @property
    def nonce_length_max(self):
        return self.nonce_length


class AES_128_GCM(_CipherMixin, aead.AESGCM):
    iana_id = CipherSuites.TLS_AES_128_GCM_SHA256
    block_size = 16
    key_length = 16
    tag_length = 12
    nonce_length = 12
    usage_limit = int(2 ** 23.5)

class AES_256_GCM(_CipherMixin, aead.AESGCM):
    iana_id = CipherSuites.TLS_AES_256_GCM_SHA384
    block_size = 16
    key_length = 32
    tag_length = 12
    nonce_length = 12
    usage_limit = int(2 ** 23.5)

class CHACHA20_POLY1305(_CipherMixin, aead.ChaCha20Poly1305):
    iana_id = CipherSuites.TLS_CHACHA20_POLY1305_SHA256
    block_size = 16
    key_length = 16
    tag_length = 12
    nonce_length = 12
    usage_limit = 1 << 64

class AES_128_CCM(_CipherMixin, aead.AESCCM):
    iana_id = CipherSuites.TLS_AES_128_CCM_SHA256
    cipher_block_size = 16
    key_length = 16
    tag_length = 12
    nonce_length = 12
    usage_limit = ...

    def __init__(self, key):
        super().__init__(key, tag_length=16)

class AES_128_CCM_8(_CipherMixin, aead.AESCCM):
    iana_id = CipherSuites.TLS_AES_128_CCM_8_SHA256
    block_size = 16
    key_length = 16
    tag_length = 12
    nonce_length = 12
    usage_limit = ...

    def __init__(self, key):
        super().__init__(key, tag_length=8)


cipher_map = {
    CipherSuites.TLS_AES_128_GCM_SHA256: AES_128_GCM,
    CipherSuites.TLS_AES_256_GCM_SHA384: AES_256_GCM,
    CipherSuites.TLS_CHACHA20_POLY1305_SHA256: CHACHA20_POLY1305,
    CipherSuites.TLS_AES_128_CCM_SHA256: AES_128_CCM,
    CipherSuites.TLS_AES_128_CCM_8_SHA256: AES_128_CCM_8,
}
digest_map = {
    CipherSuites.TLS_AES_128_GCM_SHA256: hashlib.sha256,
    CipherSuites.TLS_AES_256_GCM_SHA384: hashlib.sha384,
    CipherSuites.TLS_CHACHA20_POLY1305_SHA256: hashlib.sha256,
    CipherSuites.TLS_AES_128_CCM_SHA256: hashlib.sha256,
    CipherSuites.TLS_AES_128_CCM_8_SHA256: hashlib.sha256,
}
