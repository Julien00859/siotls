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
from siotls.crypto.key_share import resume as key_share_resume
from siotls.ciphers import cipher_suite_registry
from .. import State
from . import ServerWaitFlight2


class ServerWaitClientHello(State):
    can_send_application_data = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._is_first_client_hello = self.nconfig is None

    def process(self, client_hello):
        if client_hello.content_type != ContentType.HANDSHAKE:
            e = "Can only receive Handshake in this state."
            raise alerts.UnexpectedMessage(e)
        if client_hello.msg_type != HandshakeType.CLIENT_HELLO:
            e = "Can only receive ClientHello in this state."
            raise alerts.UnexpectedMessage(e)

        if self._is_first_client_hello:
            cipher_suite = self._find_common_cipher_suite(client_hello)
            self.nconfig = TLSNegociatedConfiguration(cipher_suite)
            self._client_unique = client_hello.random
            self._cipher = cipher_suite_registry[cipher_suite](
                'server', self.config.log_keys, self._client_unique)
            self._transcript.post_init(self._cipher.digestmod)
        else:
            if cipher_suite != self.nconfig.cipher_suite:
                e = "Client's cipher suite cannot change in between Hellos"
                raise alerts.IllegalParameter(e)
            if client_hello.random != self._client_unique:
                e = "Client's random cannot change in between Hellos"
                raise alerts.IllegalParameter(e)

        clear_extensions, encrypted_extensions, shared_key = (
            self._negociate_extensions(client_hello.extensions))

        if not shared_key:
            if not self._is_first_client_hello:
                e = "invalid KeyShare in second ClientHello"
                raise alerts.IllegalParameter(e)
            self._send_hello_retry_request(client_hello)
            self._move_to_state(ServerWaitClientHello)  # update _is_first_client_hello
            return

        self._cipher.skip_early_secrets()

        self._send_content(ServerHello(
            self._server_unique,
            client_hello.legacy_session_id,
            self.nconfig.cipher_suite,
            clear_extensions,
        ))

        if self._is_first_client_hello:
            self._send_content(ChangeCipherSpec())

        self._cipher.derive_handshake_secrets(shared_key, self._transcript.digest())

        self._send_content(EncryptedExtensions(encrypted_extensions))
        return
        self._send_content(Certificate(...))
        self._send_content(CertificateVerify(...))
        self._send_content(Finished(...))
        self._move_to_state(ServerWaitFlight2)

    def _find_common_cipher_suite(self, client_hello):
        for cipher_suite in self.config.cipher_suites:
            if cipher_suite in client_hello.cipher_suites:
                return cipher_suite
        e = "no common cipher suite found"
        raise alerts.HandshakeFailure(e)

    def _send_hello_retry_request(self, client_hello, nconfig):
        # make sure the client doesn't change its algorithms in between flights
        self.config.cipher_suites = [nconfig.cipher_suite]
        self.config.key_exchanges = [nconfig.key_exchange]
        self._send_content(HelloRetryRequest(
            HelloRetryRequest.random,
            client_hello.legacy_session_id,
            nconfig.cipher_suite,
            [
                SupportedVersionsResponse(TLSVersion.TLS_1_3),
                KeyShareRetry(nconfig.key_exchange),
            ]
        ))
        self._transcript.do_hrr_dance()
        self._send_content(ChangeCipherSpec())

    def _negociate_extensions(self, client_extensions):
        clear_extensions = [SupportedVersionsResponse(TLSVersion.TLS_1_3)]
        encrypted_extensions = []

        # Supported groups
        try:
            supported_groups = client_extensions[ExtensionType.SUPPORTED_GROUPS]
        except KeyError as exc:
            raise alerts.MissingExtension() from exc
        for group in self.config.key_exchanges:
            if group in supported_groups.named_group_list:
                self.nconfig.key_exchange = group
                break
        else:
            e = "no common key exchange found"
            raise alerts.HandshakeFailure(e)

        key_share = client_extensions.get(ExtensionType.KEY_SHARE)
        if not key_share or self.nconfig.key_exchange not in key_share.client_shares:
            return clear_extensions, encrypted_extensions, None

        # Signature algorithms
        try:
            ext = client_extensions[ExtensionType.SIGNATURE_ALGORITHMS]
        except KeyError as exc:
            raise alerts.MissingExtension() from exc
        for digital_signatures in self.config.digital_signatures:
            if digital_signatures in ext.supported_signature_algorithms:
                self.nconfig.digital_signature = digital_signatures
                break
        else:
            e = "no common digital signature found"
            raise alerts.HandshakeFailure(e)

        # Key Share
        peer_exchange = key_share.client_shares[self.nconfig.key_exchange]
        shared_key, my_exchange = key_share_resume(
            self.nconfig.key_exchange, None, peer_exchange)
        clear_extensions.append(
            KeyShareResponse(self.nconfig.key_exchange, my_exchange))

        # Max Fragment Length
        client_mfl = client_extensions.get(ExtensionType.MAX_FRAGMENT_LENGTH)
        if client_mfl:
            self.nconfig.max_fragment_length = client_mfl.octets
            encrypted_extensions.append(client_mfl)
        else:
            self.nconfig.max_fragment_length = self.config.max_fragment_length

        # ALPN
        client_alpn = client_extensions.get(
            ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
        if self.config.alpn and client_alpn:
            for proto in self.config.alpn:
                if proto in client_alpn.protocol_name_list:
                    self.nconfig.alpn = proto
                    encrypted_extensions.append(type(client_alpn)([proto]))
                    break
            else:
                raise alerts.NO_APPLICATION_PROTOCOL()
        else:
            self.nconfig.alpn = None

        # Heartbeat
        client_hb = client_extensions.get(ExtensionType.HEARTBEAT)
        server_hb = self.config.can_send_heartbeat or self.config.can_echo_heartbeat
        if client_hb and server_hb:
            self.nconfig.can_send_heartbeat = (
                self.config.can_send_heartbeat and
                client_hb.mode == HeartbeatMode.PEER_ALLOWED_TO_SEND
            )
            self.nconfig.can_echo_heartbeat = self.config.can_echo_heartbeat
            encrypted_extensions.append(Heartbeat(
                HeartbeatMode.PEER_ALLOWED_TO_SEND
                if self.config.can_echo_heartbeat else
                HeartbeatMode.PEER_NOT_ALLOWED_TO_SEND
            ))
        else:
            self.nconfig.can_send_heartbeat = False
            self.nconfig.can_echo_heartbeat = False

        return clear_extensions, encrypted_extensions, shared_key
