# class names, assert
# ruff: noqa: N801, S101
import enum
import functools
import hashlib
import hmac
from typing import ClassVar

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import aead

from siotls import key_logger
from siotls.contents import alerts
from siotls.crypto.hkdf import derive_secret, hkdf_expand_label, hkdf_extract
from siotls.iana import CipherSuites
from siotls.utils import RegistryMeta, peekable

REKEY_THRESHOLD = 1024  # arbitrary
SHA256_EMPTY = hashlib.sha256(b'').digest()
SHA256_ZEROS = b'\x00' * hashlib.sha256().digest_size
SHA384_EMPTY = hashlib.sha384(b'').digest()
SHA384_ZEROS = b'\x00' * hashlib.sha384().digest_size


class CipherState(enum.IntEnum):
    EARLY = 0
    HANDSHAKE = 1
    APPLICATION = 2


class _TLSSecrets:
    def __init__(self, digestmod, hashempty, hashzeros):
        self.state = CipherState.EARLY
        self._digestmod = digestmod
        self._hashempty = hashempty
        self._hashzeros = hashzeros
        self._salt = self._hashzeros

    def _make_deriver(self, ikm, transcript_hash, *, update_salt):
        secret = hkdf_extract(self._digestmod, self._salt, ikm)
        if update_salt:
            self._salt = derive_secret(
                self._digestmod, secret, b'derived', self._hashempty)
            self.state = CipherState(self.state + 1)
        return lambda label, *, transcript_hash=transcript_hash: (
            derive_secret(self._digestmod, secret, label, transcript_hash)
        )

    def skip_early_secrets(self):
        assert self.state is CipherState.EARLY
        psk = self._hashzeros
        self._make_deriver(psk, transcript_hash=None, update_salt=True)

    def derive_early_secrets(self, psk, psk_mode, client_hello_transcript_hash):
        assert self.state is CipherState.EARLY
        assert psk_mode in ('external', 'resume')
        psk_label = f'{psk_mode[:3]} binder'.encode()
        derive_early_secret = self._make_deriver(
            psk, client_hello_transcript_hash, update_salt=True)

        binder_key = derive_early_secret(psk_label, transcript_hash=self._hashempty)
        early_exporter_master = derive_early_secret(b'e exp master')
        client_early_traffic = derive_early_secret(b'c e traffic')

        return (
            binder_key,
            early_exporter_master,
            client_early_traffic,
        )

    def derive_handshake_secrets(self, shared_key, server_hello_transcript_hash):
        assert self.state is CipherState.HANDSHAKE
        derive_handshake_secret = self._make_deriver(
            shared_key, server_hello_transcript_hash, update_salt=True)

        client_handshake_traffic = derive_handshake_secret(b'c hs traffic')
        server_handshake_traffic = derive_handshake_secret(b's hs traffic')
        return (
            client_handshake_traffic,
            server_handshake_traffic,
        )

    def derive_master_secrets(
        self, server_finished_transcript_hash, client_finished_transcript_hash
    ):
        assert self.state is CipherState.APPLICATION
        derive_master_secret = self._make_deriver(
            self._hashzeros, server_finished_transcript_hash, update_salt=False)

        client_application_traffic = derive_master_secret(b'c ap traffic')
        server_application_traffic = derive_master_secret(b's ap traffic')
        exporter_master = derive_master_secret(b'exp master')
        resumption_master = derive_master_secret(
            b'res master', transcript_hash=client_finished_transcript_hash)
        return (
            client_application_traffic,
            server_application_traffic,
            exporter_master,
            resumption_master,
        )


class TLSCipherSuite(metaclass=RegistryMeta):
    _registry: ClassVar = {}

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if TLSCipherSuite in cls.__bases__:
            cls._registry[cls.iana_id] = cls

    iana_id: CipherSuites
    # digestmod: hashlib._Hash
    block_size: int
    key_length: int
    tag_length: int
    nonce_length: int
    usage_limit: int
    hashempty: bytes
    hashzeros: bytes

    def __init__(self, side: str, client_unique: bytes, *, log_keys: bool):
        self._secrets = _TLSSecrets(self.digestmod, self.hashempty, self.hashzeros)
        self._side = side
        self._client_unique_hex = client_unique.hex() if log_keys else ''
        self._read_cipher = self._read_iv = self._read_seq = None
        self._write_cipher = self._write_iv = self._write_seq = None

    @property
    def state(self):
        return self._secrets.state

    # ------------------------------------------------------------------
    # AEAD Encryption and Decryption
    # ------------------------------------------------------------------

    @property
    def must_decrypt(self):
        return bool(self._read_cipher)

    @property
    def must_encrypt(self):
        return bool(self._write_cipher)

    @property
    def should_rekey(self):
        return self._write_seq and (
            self._write_seq.peek() >= self.usage_limit - REKEY_THRESHOLD)

    def decrypt(self, data, associated_data):
        try:
            return self._read_cipher.decrypt(self._next_read_nonce(), data, associated_data)
        except InvalidTag as exc:
            raise alerts.DecryptError from exc

    def _next_read_nonce(self):
        nonce = self._read_iv ^ next(self._read_seq)
        return nonce.to_bytes(self.nonce_length, 'big')

    def encrypt(self, data, associated_data):
        return self._write_cipher.encrypt(self._next_write_nonce(), data, associated_data)

    def _next_write_nonce(self):
        nonce = self._write_iv ^ next(self._write_seq)
        return nonce.to_bytes(self.nonce_length, 'big')

    # ------------------------------------------------------------------
    # Finished integrity
    # ------------------------------------------------------------------

    def sign_finish(self, transcript_hash):
        key = (
            self._client_finished_key
            if self._side == 'client' else
            self._server_finished_key
        )
        return hmac.digest(key, transcript_hash, self.digestmod)

    def verify_finish(self, transcript_hash, other_verify_data):
        other_key = (
            self._server_finished_key
            if self._side == 'client' else
            self._client_finished_key
        )
        verify_data = hmac.digest(other_key, transcript_hash, self.digestmod)
        if not hmac.compare_digest(verify_data, other_verify_data):
            e = "invalid signature"
            raise ValueError(e)


    # ------------------------------------------------------------------
    # Key Derivation
    # ------------------------------------------------------------------

    @property
    def iv_length(self):
        # return max(8, self.nonce_length_min)
        return self.nonce_length

    def _derive_key_and_iv(self, secret):
        dm = self.digestmod
        return (
            hkdf_expand_label(dm, secret, b'key', b'', self.key_length),
            hkdf_expand_label(dm, secret, b'iv', b'', self.iv_length),
        )

    def skip_early_secrets(self):
        self._secrets.skip_early_secrets()

    def derive_early_secrets(self, psk, psk_mode, client_hello_transcript_hash):
        binder_key, early_exporter_master, client_early_traffic = (
            self._secrets.derive_early_secrets(
                psk, psk_mode, client_hello_transcript_hash))

        client_key, client_iv = (self._derive_key_and_iv(client_early_traffic))
        if self._side == 'client':
            self._write_cipher = self._ciphermod(client_key)
            self._write_iv = int.from_bytes(client_iv, 'big')
            self._write_seq = peekable(iter(range(self.usage_limit)))
        else:
            self._read_cipher = self._ciphermod(client_key)
            self._read_iv = int.from_bytes(client_iv, 'big')
            self._read_seq = peekable(iter(range(self.usage_limit)))

        if self._client_unique_hex:
            key_logger.info("CLIENT_EARLY_TRAFFIC_SECRET %s %s",
                self._client_unique_hex, client_early_traffic.hex())

        return binder_key, early_exporter_master

    def derive_handshake_secrets(self, shared_key, server_hello_transcript_hash):
        client_handshake_traffic, server_handshake_traffic = (
            self._secrets.derive_handshake_secrets(
                shared_key, server_hello_transcript_hash))

        self._client_finished_key = derive_secret(
            self.digestmod, client_handshake_traffic, b"finished", b"")
        self._server_finished_key =  derive_secret(
            self.digestmod, server_handshake_traffic, b"finished", b"")

        client_key, client_iv = self._derive_key_and_iv(client_handshake_traffic)
        server_key, server_iv = self._derive_key_and_iv(server_handshake_traffic)
        if self._side == 'client':
            self._write_cipher = self._ciphermod(client_key)
            self._write_iv = int.from_bytes(client_iv, 'big')
            self._write_seq = peekable(iter(range(self.usage_limit)))
            self._read_cipher = self._ciphermod(server_key)
            self._read_iv = int.from_bytes(server_iv, 'big')
            self._read_seq = peekable(iter(range(self.usage_limit)))
        else:
            self._write_cipher = self._ciphermod(server_key)
            self._write_iv = int.from_bytes(server_iv, 'big')
            self._write_seq = peekable(iter(range(self.usage_limit)))
            self._read_cipher = self._ciphermod(client_key)
            self._read_iv = int.from_bytes(client_iv, 'big')
            self._read_seq = peekable(iter(range(self.usage_limit)))

        if self._client_unique_hex:
            key_logger.info("CLIENT_HANDSHAKE_TRAFFIC_SECRET %s %s",
                self._client_unique_hex, client_handshake_traffic.hex())
            key_logger.info("SERVER_HANDSHAKE_TRAFFIC_SECRET %s %s",
                self._client_unique_hex, server_handshake_traffic.hex())

    def derive_master_secrets(
        self, server_finished_transcript_hash, client_finished_transcript_hash
    ):
        (
            client_application_traffic,
            server_application_traffic,
            exporter_master,
            resumption_master
        ) = self._secrets.derive_master_secrets(
            server_finished_transcript_hash,
            client_finished_transcript_hash
        )

        client_key, client_iv = self._derive_key_and_iv(client_application_traffic)
        server_key, server_iv = self._derive_key_and_iv(server_application_traffic)
        if self._side == 'client':
            self._write_cipher = self._ciphermod(client_key)
            self._write_iv = int.from_bytes(client_iv, 'big')
            self._write_seq = peekable(iter(range(self.usage_limit)))
            self._read_cipher = self._ciphermod(server_key)
            self._read_iv = int.from_bytes(server_iv, 'big')
            self._read_seq = peekable(iter(range(self.usage_limit)))
        else:
            self._write_cipher = self._ciphermod(server_key)
            self._write_iv = int.from_bytes(server_iv, 'big')
            self._write_seq = peekable(iter(range(self.usage_limit)))
            self._read_cipher = self._ciphermod(client_key)
            self._read_iv = int.from_bytes(client_iv, 'big')
            self._read_seq = peekable(iter(range(self.usage_limit)))

        # not necessary anymore
        self._client_finished_key = None
        self._server_finished_key = None

        if self._client_unique_hex:
            key_logger.info("CLIENT_TRAFFIC_SECRET_0 %s %s",
                self._client_unique_hex, client_application_traffic.hex())
            key_logger.info("SERVER_TRAFFIC_SECRET_0 %s %s",
                self._client_unique_hex, server_application_traffic.hex())
            key_logger.info("EXPORTER_SECRET %s %s",
                self._client_unique_hex, exporter_master.hex())

        return exporter_master, resumption_master


class TLS_AES_128_GCM_SHA256(TLSCipherSuite):
    iana_id = CipherSuites.TLS_AES_128_GCM_SHA256
    _ciphermod = aead.AESGCM
    digestmod = hashlib.sha256
    block_size = 16
    key_length = 16
    tag_length = 16
    nonce_length = 12
    usage_limit = int(2 ** 23.5)
    hashempty = SHA256_EMPTY
    hashzeros = SHA256_ZEROS

class TLS_AES_256_GCM_SHA384(TLSCipherSuite):
    iana_id = CipherSuites.TLS_AES_256_GCM_SHA384
    _ciphermod = aead.AESGCM
    digestmod = hashlib.sha384
    block_size = 16
    key_length = 32
    tag_length = 16
    nonce_length = 12
    usage_limit = int(2 ** 23.5)
    hashempty = SHA384_EMPTY
    hashzeros = SHA384_ZEROS

class TLS_CHACHA20_POLY1305_SHA256(TLSCipherSuite):
    iana_id = CipherSuites.TLS_CHACHA20_POLY1305_SHA256
    _ciphermod = aead.ChaCha20Poly1305
    digestmod = hashlib.sha256
    block_size = 16
    key_length = 32
    tag_length = 16
    nonce_length = 12
    usage_limit = 1 << 64
    hashempty = SHA256_EMPTY
    hashzeros = SHA256_ZEROS

class TLS_AES_128_CCM_SHA256(TLSCipherSuite):
    iana_id = CipherSuites.TLS_AES_128_CCM_SHA256
    _ciphermod = aead.AESCCM
    digestmod = hashlib.sha256
    block_size = 16
    key_length = 16
    tag_length = 16
    nonce_length = 12
    usage_limit = ...
    hashempty = SHA256_EMPTY
    hashzeros = SHA256_ZEROS

class TLS_AES_128_CCM_8_SHA256(TLSCipherSuite):
    iana_id = CipherSuites.TLS_AES_128_CCM_8_SHA256
    _ciphermod = functools.partial(aead.AESCCM, tag_length=8)
    digestmod = hashlib.sha256
    block_size = 16
    key_length = 16
    tag_length = 8
    nonce_length = 12
    usage_limit = ...
    hashempty = SHA256_EMPTY
    hashzeros = SHA256_ZEROS
