from types import SimpleNamespace
from siotls import key_logger
from siotls.iana import (
    ContentType,
    HandshakeType,
    HeartbeatMode,
    ExtensionType,
    TLSVersion,
)
from siotls.configuration import TLSNegociatedConfiguration
from siotls.contents import alerts, ChangeCipherSpec
from siotls.contents.handshakes import (
    HelloRetryRequest,
    ServerHello,
    EncryptedExtensions,
    Certificate,
    CertificateVerify,
    Finished,
)
from siotls.contents.handshakes.extensions import (
    SupportedVersionsResponse,
    KeyShareResponse, KeyShareRetry,
    Heartbeat,
)
from siotls.ciphers import digest_map
from siotls.crypto.key_share import resume as key_share_resume
from siotls.secrets import TLSSecrets
from .. import State
from . import ServerWaitFlight2


class ServerWaitClientHello(State):
    can_send_application_data = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._is_first_client_hello = not bool(self._transcript_hash)

    def process(self, client_hello):
        if client_hello.content_type != ContentType.HANDSHAKE:
            e = "Can only receive Handshake in this state."
            raise alerts.UnexpectedMessage(e)
        if client_hello.msg_type != HandshakeType.CLIENT_HELLO:
            e = "Can only receive ClientHello in this state."
            raise alerts.UnexpectedMessage(e)

        if _ := client_hello.extensions.get(ExtensionType.PRE_SHARED_KEY):
            raise NotImplementedError("todo")

        nconfig = SimpleNamespace()  # TODO: scrap SN
        self._negociate_algorithms(client_hello, nconfig)

        if self._is_first_client_hello:
            digestmod = digest_map[nconfig.cipher_suite]
            self._transcript_hash = digestmod(self._last_client_hello)
            self._last_client_hello = None
            self._client_unique = client_hello.random
        else:
            if client_hello.random != self._client_unique:
                e = "Client's random cannot change in between Hellos"
                raise alerts.IllegalParameter(e)

        if not self._can_resume_key_share(client_hello, nconfig.key_exchange):
            self._send_hello_retry_request(client_hello, nconfig)
            self._move_to_state(ServerWaitClientHello)  # update _is_first_client_hello
            return

        clear_extensions, encrypted_extensions, shared_key = (
            self._negociate_extensions(client_hello.extensions, nconfig))

        self.nconfig = TLSNegociatedConfiguration(**vars(nconfig))
        self.secrets = TLSSecrets(
            self.nconfig.digestmod,
            max(8, self.nconfig.ciphermod.nonce_length_min),
        )
        self.secrets.skip_early_secrets()

        self._send_content(ServerHello(
            self._server_unique,
            client_hello.legacy_session_id,
            nconfig.cipher_suite,
            clear_extensions,
        ))

        if self._is_first_client_hello:
            self._send_content(ChangeCipherSpec())


        self._cipher.skip_early_secrets()
        self._client.derive_handshake_secrets(shared_key, self._transcript.digest())

        self._send_content(EncryptedExtensions(encrypted_extensions))
        self._send_content(Certificate(...))
        self._send_content(CertificateVerify(...))
        self._send_content(Finished(...))
        self._move_to_state(ServerWaitFlight2)

    def _negociate_algorithms(self, client_hello):
        self.nconfig.cipher_suite = self._find_common_cipher_suite(client_hello)
        self.nconfig.digital_signature = self._find_common_digital_signature(client_hello)
        self.nconfig.key_exchange = self._find_common_key_exchange(client_hello)

    def _find_common_cipher_suite(self, client_hello):
        for cipher_suite in self.config.cipher_suites:
            if cipher_suite in client_hello.cipher_suites:
                return cipher_suite
        e = "no common cipher suite found"
        raise alerts.HandshakeFailure(e)

    def _find_common_digital_signature(self, client_hello):
        try:
            ext = client_hello.extensions[ExtensionType.SIGNATURE_ALGORITHMS]
        except KeyError as exc:
            raise alerts.MissingExtension() from exc
        for digital_signatures in self.config.digital_signatures:
            if digital_signatures in ext.supported_signature_algorithms:
                return digital_signatures
        e = "no common digital signature found"
        raise alerts.HandshakeFailure(e)

    def _find_common_key_exchange(self, client_hello):
        try:
            supported_groups = client_hello.extensions[ExtensionType.SUPPORTED_GROUPS]
        except KeyError as exc:
            raise alerts.MissingExtension() from exc
        for group in self.config.key_exchanges:
            if group in supported_groups.named_group_list:
                return group
        e = "no common key exchange found"
        raise alerts.HandshakeFailure(e)

    def _can_resume_key_share(self, client_hello):
        key_share = client_hello.extensions.get(ExtensionType.KEY_SHARE)
        return key_share and self.nconfig.key_exchange in key_share.client_shares

    def _send_hello_retry_request(self, client_hello, nconfig):
        if not self._is_first_client_hello:
            e = "invalid KeyShare in second ClientHello"
            raise alerts.IllegalParameter(e)

        # make sure the client doesn't change its algorithms in between flights
        self.config.cipher_suites = [nconfig.cipher_suite]
        self.config.digital_signatures = [nconfig.digital_signature]
        self.config.key_exchanges = [nconfig.key_exchange]

        # RFC 8446 4.4.1 shenanigans regarding HelloRetryRequest
        digestmod = digest_map[nconfig.cipher_suite]
        self._transcript_hash = digestmod(b''.join([
            HandshakeType.MESSAGE_HASH.to_bytes(1, 'big'),
            digestmod().digest_size.to_bytes(3, 'big'),
            self._transcript_hash.digest(),
        ]))

        self._send_content(HelloRetryRequest(
            HelloRetryRequest.random,
            client_hello.legacy_session_id,
            nconfig.cipher_suite,
            [
                SupportedVersionsResponse(TLSVersion.TLS_1_3),
                KeyShareRetry(nconfig.key_exchange),
            ]
        ))
        self._send_content(ChangeCipherSpec())

    def _negociate_extensions(self, client_extensions, nconfig):
        clear_extensions = [SupportedVersionsResponse(TLSVersion.TLS_1_3)]
        encrypted_extensions = []

        # Key Share
        key_share = client_extensions[ExtensionType.KEY_SHARE]
        peer_exchange = key_share.client_shares[nconfig.key_exchange]
        shared_key, my_exchange = key_share_resume(
            nconfig.key_exchange, None, peer_exchange)
        clear_extensions.append(
            KeyShareResponse(nconfig.key_exchange, my_exchange))

        # Max Fragment Length
        client_mfl = client_extensions.get(ExtensionType.MAX_FRAGMENT_LENGTH)
        if client_mfl:
            nconfig.max_fragment_length = client_mfl.octets
            encrypted_extensions.append(client_mfl)
        else:
            nconfig.max_fragment_length = self.config.max_fragment_length

        # ALPN
        client_alpn = client_extensions.get(
            ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
        if self.config.alpn and client_alpn:
            for proto in self.config.alpn:
                if proto in client_alpn.protocol_name_list:
                    nconfig.alpn = proto
                    encrypted_extensions.append(type(client_alpn)([proto]))
                    break
            else:
                raise alerts.NO_APPLICATION_PROTOCOL()
        else:
            nconfig.alpn = None

        # Heartbeat
        client_hb = client_extensions.get(ExtensionType.HEARTBEAT)
        server_hb = self.config.can_send_heartbeat or self.config.can_echo_heartbeat
        if client_hb and server_hb:
            nconfig.can_send_heartbeat = (
                self.config.can_send_heartbeat and
                client_hb.mode == HeartbeatMode.PEER_ALLOWED_TO_SEND
            )
            nconfig.can_echo_heartbeat = self.config.can_echo_heartbeat
            encrypted_extensions.append(Heartbeat(
                HeartbeatMode.PEER_ALLOWED_TO_SEND
                if self.config.can_echo_heartbeat else
                HeartbeatMode.PEER_NOT_ALLOWED_TO_SEND
            ))
        else:
            nconfig.can_send_heartbeat = False
            nconfig.can_echo_heartbeat = False

        return clear_extensions, encrypted_extensions, shared_key
