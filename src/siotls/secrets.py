from siotls.crypto.hkdf import hkdf_extract, hkdf_expand_label, derive_secret


class TLSSecrets:
    def __init__(self, digestmod, iv_length):
        self._digestmod = digestmod
        self._iv_length = iv_length
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

    def _derive_key_and_iv(self, secret):
        dm = self._digestmod
        return (
            hkdf_expand_label(dm, secret, b'key', b'', dm.digest_size),
            hkdf_expand_label(dm, secret, b'iv', b'', self._iv_length),
        )

    def skip_early_secrets(self):
        psk = self._zeros
        self._make_deriver(psk, transcript_hash=None, update_salt=True)

    def compute_early_secrets(self, psk, psk_mode, client_hello_transcript_hash):
        assert psk_mode in ('external', 'resume')
        psk_label = f'{psk_mode[:3]} binder'.encode()
        derive_early_secret = self._make_deriver(
            psk, client_hello_transcript_hash, update_salt=True)

        binder_key = derive_early_secret(psk_label, transcript_hash=self._empty)
        early_exporter_master = derive_early_secret(b'e exp master')
        client_early_traffic = derive_early_secret(b'c e traffic')
        client_early_traffic_key, client_early_traffic_iv = (
            self._derive_key_and_iv(client_early_traffic))
        return (
            binder_key,
            early_exporter_master,
            client_early_traffic_key,
            client_early_traffic_iv,
        )

    def compute_handshake_secrets(self, shared_key, server_hello_transcript_hash):
        derive_handshake_secret = self._make_deriver(
            shared_key, server_hello_transcript_hash, update_salt=True)

        client_handshake_traffic = derive_handshake_secret(b'c hs traffic')
        client_handshake_traffic_key, client_handshake_traffic_iv = (
            self._derive_key_and_iv(client_handshake_traffic))
        server_handshake_traffic = derive_handshake_secret(b's hs traffic')
        server_handshake_traffic_key, server_handshake_traffic_iv = (
            self._derive_key_and_iv(server_handshake_traffic))
        return (
            client_handshake_traffic_key,
            client_handshake_traffic_iv,
            server_handshake_traffic_key,
            server_handshake_traffic_iv,
        )

    def compute_master_secrets(
        self, server_finished_transcript_hash, client_finished_transcript_hash
    ):
        derive_master_secret = self._make_deriver(
            self._zeros, server_finished_transcript_hash, update_salt=False)

        client_application_traffic = derive_master_secret(b'c ap traffic')
        client_application_traffic_key, client_application_traffic_iv = (
            self._derive_key_and_iv(client_application_traffic))
        server_application_traffic = derive_master_secret(b's ap traffic')
        server_application_traffic_key, server_application_traffic_iv = (
            self._derive_key_and_iv(server_application_traffic))
        exporter_master = derive_master_secret(b'exp master')
        resumption_master = derive_master_secret(
            b'res master', transcript_hash=client_finished_transcript_hash)
        return (
            client_application_traffic_key,
            client_application_traffic_iv,
            server_application_traffic_key,
            server_application_traffic_iv,
            exporter_master,
            resumption_master,
        )
