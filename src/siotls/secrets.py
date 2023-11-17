# TODO: store and manipulate those secrets more safely
# https://keepassxc.org/blog/2019-02-21-memory-security/

from siotls.crypto.hkdf import hkdf_extract, derive_secret


class TLSSecrets:
    binder_key: bytes
    client_early_traffic: bytes
    early_exporter_master: bytes
    client_handshake_traffic: bytes
    server_handshake_traffic: bytes
    client_application_traffic: bytes
    server_application_traffic: bytes
    exporter_master: bytes
    resumption_master: bytes

    def __init__(self, digestmod):
        self._digestmod = digestmod
        self._zeros = b'\x00' * digestmod().digest_size
        self._salt = self._zeros
        self._empty = digestmod(b'').digest()

    def _make_deriver(self, input_keying_material, transcript_hash, *, update_salt):
        secret = hkdf_extract(
            self._digestmod,
            salt=self._salt,
            input_keying_material=input_keying_material
        )
        if update_salt:
            self._salt = derive_secret(
                self._digestmod, secret, b'derived', self._empty)
        return lambda label, *, transcript_hash=transcript_hash: (
            derive_secret(self._digestmod, secret, label, transcript_hash)
        )

    def skip_early_secrets(self):
        psk = self._zeros
        self._make_deriver(psk, transcript_hash=None, update_salt=True)

    def compute_early_secrets(self, psk, psk_mode, client_hello_transcript_hash):
        assert psk_mode in ('external', 'resume')
        psk_label = f'{psk_mode[:3]} binder'.encode()

        derive_early_secret = self._make_deriver(
            psk, client_hello_transcript_hash, update_salt=True)
        self.binder_key = derive_early_secret(psk_label, transcript_hash=self._empty)
        self.client_early_traffic = derive_early_secret(b'c e traffic')
        self.early_exporter_master = derive_early_secret(b'e exp master')

    def compute_handshake_secrets(self, shared_key, server_hello_transcript_hash):
        derive_handshake_secret = self._make_deriver(
            shared_key, server_hello_transcript_hash, update_salt=True)
        self.client_handshake_traffic = derive_handshake_secret(b'c hs traffic')
        self.server_handshake_traffic = derive_handshake_secret(b's hs traffic')

    def compute_master_secrets(
        self, server_finished_transcript_hash, client_finished_transcript_hash
    ):
        derive_master_secret = self._make_deriver(
            self._zeros, server_finished_transcript_hash, update_salt=False)
        self.client_application_traffic = derive_master_secret(b'c ap traffic')
        self.server_application_traffic = derive_master_secret(b's ap traffic')
        self.exporter_master = derive_master_secret(b'exp master')
        self.resumption_master = derive_master_secret(
            b'res master', transcript_hash=client_finished_transcript_hash)
