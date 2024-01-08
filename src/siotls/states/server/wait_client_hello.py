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
    ApplicationLayerProtocolNegotiation as ALPN,
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
            self._send_hello_retry_request(client_hello, clear_extensions)
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

    def _send_hello_retry_request(self, client_hello, clear_extensions):
        # make sure the client doesn't change its algorithms in between flights
        self.config.cipher_suites = [self.nconfig.cipher_suite]
        self.config.key_exchanges = [self.nconfig.key_exchange]

        self._send_content(HelloRetryRequest(
            HelloRetryRequest.random,
            client_hello.legacy_session_id,
            nconfig.cipher_suite,
            clear_extensions,
        ))
        self._transcript.do_hrr_dance()
        self._send_content(ChangeCipherSpec())

    def _negociate_extensions(self, client_extensions):
        clear_extensions = []
        encrypted_extensions = []

        def negociate(ext_name, *args, **kwargs):
            ext_type = getattr(ExtensionType, ext_name.upper())
            ext = client_extensions.get(ext_type)
            meth = getattr(self, f'_negociate_{ext_name}')
            clear_exts, encrypted_exts, *rest = meth(ext, *args, **kwargs)
            clear_extensions.extend(clear_exts)
            encrypted_extensions.extend(encrypted_exts)
            return rest[0] if rest else None

        negociate('supported_versions')
        negociate('supported_groups')
        negociate('signature_algorithms')

        shared_key = negociate('key_share')
        if not shared_key:
            return clear_extensions, encrypted_extensions, None

        negociate('max_fragment_length')
        negociate('application_layer_protocol_negotiation')
        negociate('heartbeat')

        return clear_extensions, encrypted_extensions, shared_key

    def _negociate_supported_versions(self, supported_versions_ext):
        if not supported_versions_ext:
            raise MissingExtension(ExtensionType.SUPPORTED_VERSIONS)
        if TLSVersion.TLS_1_3 not in supported_versions_ext.versions:
            raise NotImplementedError("todo")  # unclear spec
        return [SupportedVersionsResponse(TLSVersion.TLS_1_3)], []

    def _negociate_supported_groups(self, supported_groups_ext):
        if not supported_groups_ext:
            raise alerts.MissingExtension(ExtensionType.SUPPORTED_GROUPS)
        for group in self.config.key_exchanges:
            if group in supported_groups_ext.named_group_list:
                self.nconfig.key_exchange = group
                return [], []
        e = "no common key exchange found"
        raise alerts.HandshakeFailure(e)

    def _negociate_signature_algorithms(self, sa_ext):
        if not sa_ext:
            raise alerts.MissingExtension(ExtensionType.SIGNATURE_ALGORITHMS)
        for signature_algorithms in self.config.signature_algorithms:
            if signature_algorithms in sa_ext.supported_signature_algorithms:
                self.nconfig.signature_algorithm = signature_algorithms
                return [], []
        e = "no common digital signature found"
        raise alerts.HandshakeFailure(e)

    def _negociate_key_share(self, key_share_ext):
        key_exchange = self.nconfig.key_exchange
        if key_share_ext and key_exchange in key_share_ext.client_shares:
            # possible to resume key share => ServerHello
            peer_exchange = key_share_ext.client_shares[key_exchange]
            shared_key, my_exchange = key_share_resume(
                key_exchange, None, peer_exchange)
            response = KeyShareResponse(key_exchange, my_exchange)
        else:
            # impossible to resume key share => HelloRetryRequest
            shared_key = None
            response = KeyShareRetry(key_exchange)
        return [response], [], shared_key

    def _negociate_max_fragment_length(self, mfl_ext):
        if mfl_ext:
            self.nconfig.max_fragment_length = mfl_ext.octets
            return [], [mfl_ext]

        self.nconfig.max_fragment_length = self.config.max_fragment_length
        return [], []

    def _negociate_application_layer_protocol_negotiation(self, alpn_ext):
        if not alpn_ext or not self.config.alpn:
            self.nconfig.alpn = None
            return [], []
        for proto in self.config.alpn:
            if proto in alpn_ext.protocol_name_list:
                self.nconfig.alpn = proto
                return [], [ALPN([proto])]
        e = "no common application layer protocol found"
        raise alerts.NoApplicationProtocol(e)

    def _negociate_heartbeat(self, client_hb):
        server_hb = self.config.can_send_heartbeat or self.config.can_echo_heartbeat
        if client_hb and server_hb:
            self.nconfig.can_send_heartbeat = (
                self.config.can_send_heartbeat and
                client_hb.mode == HeartbeatMode.PEER_ALLOWED_TO_SEND
            )
            self.nconfig.can_echo_heartbeat = self.config.can_echo_heartbeat
            response = Heartbeat(
                HeartbeatMode.PEER_ALLOWED_TO_SEND
                if self.config.can_echo_heartbeat else
                HeartbeatMode.PEER_NOT_ALLOWED_TO_SEND
            )
            return [], [response]

        self.nconfig.can_send_heartbeat = False
        self.nconfig.can_echo_heartbeat = False
        return [], []
