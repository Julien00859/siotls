import hashlib
from cryptography.hazmat.primitives.ciphers import aead
from siotls.iana import CipherSuites
from siotls.utils import peekable
from siotls.secrets import TLSSecrets

REKEY_THRESHOLD = 1024  # arbitrary
cipher_suite_registry = {}


class _TLSCipher:
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if _TLSCipher in cls.__bases__:
            cipher_suite_registry[cls.iana_id] = cls

    @property
    def nonce_length_min(self):
        return self.nonce_length

    @property
    def nonce_length_max(self):
        return self.nonce_length


    def __init__(self, side):
        self.side = side
        self._secrets = TLSSecrets(self._digestmod, max(8, self.nonce_length_min))
        self._read_cipher, self._read_iv, self._read_seq = None
        self._write_cipher, self._write_iv, self._write_seq = None

    def decrypt(self, data, associated_data):
        return self._read_cipher.decrypt(self._next_read_nonce(), data, associated_data)

    def _next_read_nonce(self):
        nonce = self._read_iv ^ next(self._read_seq)
        return nonce.to_bytes(self.nonce_length, 'big')

    def encrypt(self, data, associated_data):
        return self._write_cipher.encrypt(self._next_write_nonce(), data, associated_data)

    def _next_write_nonce(self):
        nonce = self._write_iv ^ next(self._write_seq)
        return nonce.to_bytes(self.nonce_length, 'big')

    @property
    def should_rekey(self):
        return self._write_seq and (
            self._write_seq.peek() >= self.usage_limit - REKEY_THRESHOLD
        )

    def skip_early_secrets(self):
        self._secrets.skip_early_secrets()

    def derive_early_secrets(self, psk, psk_mode, client_hello_transcript_hash):
        (
            binder_key,
            early_exporter_master,
            client_early_traffic_key,
            client_early_traffic_iv,
        ) = self._secrets.derive_early_secrets(
            psk,
            psk_mode,
            client_hello_transcript_hash,
        )
        if self.side == 'client':
            self._write_cipher = self.ciphermod(client_early_traffic_key)
            self._write_iv = int.from_bytes(client_early_traffic_iv, 'big')
            self._write_seq = peekable(iter(range(self.usage_limit)))
        else:
            self._read_cipher = self.ciphermod(client_early_traffic_key)
            self._read_iv = int.from_bytes(client_early_traffic_iv, 'big')
            self._read_seq = peekable(iter(range(self.usage_limit)))
        return binder_key, early_exporter_master

    def derive_handshake_secrets(self, shared_key, server_hello_transcript_hash):
        (
            client_handshake_traffic_key,
            client_handshake_traffic_iv,
            server_handshake_traffic_key,
            server_handshake_traffic_iv,
        ) = self._secrets.derive_handshake_secrets(
            shared_key,
            server_hello_transcript_hash,
        )
        if self.side == 'client':
            self._write_cipher = self.ciphermod(client_handshake_traffic_key)
            self._write_iv = int.from_bytes(client_handshake_traffic_iv, 'big')
            self._write_seq = peekable(iter(range(self.usage_limit)))
            self._read_cipher = self.ciphermod(server_handshake_traffic_key)
            self._read_iv = int.from_bytes(server_handshake_traffic_iv, 'big')
            self._read_seq = peekable(iter(range(self.usage_limit)))
        else:
            self._write_cipher = self.ciphermod(server_handshake_traffic_key)
            self._write_iv = int.from_bytes(server_handshake_traffic_iv, 'big')
            self._write_seq = peekable(iter(range(self.usage_limit)))
            self._read_cipher = self.ciphermod(client_handshake_traffic_key)
            self._read_iv = int.from_bytes(client_handshake_traffic_iv, 'big')
            self._read_seq = peekable(iter(range(self.usage_limit)))

    def derive_master_secrets(
        self, server_finished_transcript_hash, client_finished_transcript_hash
    ):
        (
            client_application_traffic_key,
            client_application_traffic_iv,
            server_application_traffic_key,
            server_application_traffic_iv,
            exporter_master,
            resumption_master,
        ) = self._secrets.derive_master_secrets(
            server_finished_transcript_hash,
            client_finished_transcript_hash,
        )
        if self.side == 'client':
            self._write_cipher = self.ciphermod(client_application_traffic_key)
            self._write_iv = int.from_bytes(client_application_traffic_iv, 'big')
            self._write_seq = peekable(iter(range(self.usage_limit)))
            self._read_cipher = self.ciphermod(server_application_traffic_key)
            self._read_iv = int.from_bytes(server_application_traffic_iv, 'big')
            self._read_seq = peekable(iter(range(self.usage_limit)))
        else:
            self._write_cipher = self.ciphermod(server_application_traffic_key)
            self._write_iv = int.from_bytes(server_application_traffic_iv, 'big')
            self._write_seq = peekable(iter(range(self.usage_limit)))
            self._read_cipher = self.ciphermod(client_application_traffic_key)
            self._read_iv = int.from_bytes(client_application_traffic_iv, 'big')
            self._read_seq = peekable(iter(range(self.usage_limit)))
        return exporter_master, resumption_master



class TLS_AES_128_GCM_SHA256(_TLSCipher):
    iana_id = CipherSuites.TLS_AES_128_GCM_SHA256
    _ciphermod = aead.AESGCM
    _digestmod = hashlib.sha256
    block_size = 16
    key_length = 16
    tag_length = 12
    nonce_length = 12
    usage_limit = int(2 ** 23.5)

class TLS_AES_256_GCM_SHA384(_TLSCipher):
    iana_id = CipherSuites.TLS_AES_256_GCM_SHA384
    _ciphermod = aead.AESGCM
    _digestmod = hashlib.sha384
    block_size = 16
    key_length = 32
    tag_length = 12
    nonce_length = 12
    usage_limit = int(2 ** 23.5)

class TLS_CHACHA20_POLY1305_SHA256(_TLSCipher):
    iana_id = CipherSuites.TLS_CHACHA20_POLY1305_SHA256
    _ciphermod = aead.ChaCha20Poly1305
    _digestmod = hashlib.sha256
    block_size = 16
    key_length = 16
    tag_length = 12
    nonce_length = 12
    usage_limit = 1 << 64

class TLS_AES_128_CCM_SHA256(_TLSCipher):
    iana_id = CipherSuites.TLS_AES_128_CCM_SHA256
    _ciphermod = aead.AESCCM
    _digestmod = hashlib.sha256
    cipher_block_size = 16
    key_length = 16
    tag_length = 12
    nonce_length = 12
    usage_limit = ...

class AESCCM8(aead.AESCCM):
    def __init__(self, key):
        super().__init__(key, tag_length=8)

class TLS_AES_128_CCM_8_SHA256(_TLSCipher):
    iana_id = CipherSuites.TLS_AES_128_CCM_8_SHA256
    _ciphermod = AESCCM8
    _digestmod = hashlib.sha256
    block_size = 16
    key_length = 16
    tag_length = 12
    nonce_length = 12
    usage_limit = ...
