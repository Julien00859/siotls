from types import SimpleNamespace
from siotls.secrets import TLSSecrets
from siotls.crypto.key_share import resume as key_share_resume
from siotls.contents import alerts, ChangeCipherSpec
from siotls.iana import (
    ContentType,
    HandshakeType,
    HandshakeType_,
    HeartbeatMode,
    ExtensionType
)
from .. import State
from . import ClientWaitEncryptedExtensions


class ClientWaitServerHello(State):
    can_send_application_data = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._is_first_server_hello = not bool(self._transcript_hash)

    def process(self, content):
        if content.content_type != ContentType.HANDSHAKE:
            e = "Can only receive Handshake in this state."
            raise alerts.UnexpectedMessage(e)
        if self._is_first_server_hello:
            if content.msg_type != HandshakeType.SERVER_HELLO:
                e =("Can only receive ServerHello or HelloRetryRequest "
                    "in this state.")
                raise alerts.UnexpectedMessage(e)
        else:
            if content.msg_type is not HandshakeType.SERVER_HELLO:
                e = "Can only receive ServerHello in this state."
                raise alerts.UnexpectedMessage(e)

        if content.cipher_suite not in self.config.cipher_suites:
            e =(f"The server's selected {content.cipher_suite} wasn't offered "
                f"in ClientHello: {self.config.cipher_suites}")
            raise alerts.IllegalParameter(e)

        digestmod = content.cipher_suite.digestmod
        self._transcript_hash = digestmod(self._last_client_hello)
        self._last_client_hello = None

        if self._is_first_server_hello:
            self._send_content(ChangeCipherSpec())

        if content.msg_type is HandshakeType_.HELLO_RETRY_REQUEST:
            self._process_hello_retry_request(content)
        else:
            self._process_server_hello(content)

    def _process_hello_retry_request(self, hello_retry_request):
        from . import ClientStart

        key_share = hello_retry_request.extensions.get(ExtensionType.KEY_SHARE)
        if not key_share:
            e = "Missing Key Share in HelloRetryRequest"
            raise alerts.MissingExtension(e)
        if key_share.selected_group not in self.config.key_exchanges:
            e =(f"The server's selected {key_share.selected_group} wasn't "
                f"offered in ClientHello: {self.config.key_exchanges}")
            raise alerts.IllegalParameter(e)

        # make sure we select the algorithms selected by the server
        self.config.cipher_suites = [hello_retry_request.cipher_suite]
        self.config.key_exchanges = [key_share.selected_group]

        if cookie := hello_retry_request.extensions.get(ExtensionType.COOKIE):
            self._cookie = cookie.cookie

        # RFC 8446 4.4.1 shenanigans regarding HelloRetryRequest
        digestmod = hello_retry_request.cipher_suite.digestmod
        self._transcript_hash = digestmod(b''.join([
            HandshakeType.MESSAGE_HASH.to_bytes(1, 'big'),
            digestmod().digest_size.to_bytes(3, 'big'),
            self._transcript_hash.digest(),
            self._last_server_hello,
        ]))
        self._last_server_hello = None

        self._move_to_state(ClientStart)
        self.connection.initiate_connection()

    def _process_server_hello(self, server_hello):
        self._server_unique = server_hello.random

        nconfig = SimpleNamespace()
        nconfig.cipher_suite = server_hello.cipher_suite
        nconfig.secrets = TLSSecrets(nconfig.cipher_suite.digestmod)
        nconfig.secrets.skip_early_secrets()

        self._transcript_hash.update(self._last_server_hello)
        self._last_server_hello = None
        shared_key = self._negociate_extensions(server_hello.extensions, nconfig)
        nconfig.secrets.compute_handshake_secrets(
            shared_key, self._transcript_hash.digest())

        # save the simple namespace on the connection as we don't know
        # the negociated digital signature yet, delegate instantiating
        # the final NegociatedConfiguration object to WaitCertificate
        self.nconfig = nconfig

        self._move_to_state(ClientWaitEncryptedExtensions)

    def _negociate_extensions(self, server_extensions, nconfig):
        # Key Share
        try:
            key_share = server_extensions[ExtensionType.KEY_SHARE]
        except KeyError as exc:
            raise alerts.MissingExtension() from exc
        if key_share.group not in self._key_shares:
            e =(f"The server's selected {key_share.selected_group} wasn't "
                f"offered in ClientHello: {self.config.key_exchanges}")
            raise alerts.IllegalParameter(e)
        shared_key, _ = key_share_resume(
            nconfig.key_exchange,
            self._key_shares[nconfig.key_exchange],
            key_share.client_shares[nconfig.key_exchange],
        )
        nconfig.key_exchange = key_share.group

        # Max Fragment Length
        mfl = server_extensions.get(ExtensionType.MAX_FRAGMENT_LENGTH)
        if self.config.max_fragment_length != 16384 and mfl:
            if mfl.max_fragment_length != self.config.max_fragment_length:
                e =(f"The server's selected {mfl.max_fragment_length} max "
                    f"fragment length wasn't offered in ClientHello:"
                    f"{self.config.key_exchanges}")
                raise alerts.IllegalParameter(e)
            nconfig.max_fragment_length = mfl.max_fragment_length

        # ALPN
        alpn = server_extensions.get(
            ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
        if alpn:
            if length := len(alpn.protocol_name_list) != 1:
                e =("Invalid Application Layer Protocol Negociation (ALPN) "
                    f"response. 1 protocol expected, {length} found.")
                raise alerts.IllegalParameter(e)
            if alpn.protocol_name_list[0] not in self.config.alpn:
                e =(f"The server's selected application layer protocol (ALPN) "
                    f"{alpn.protocol_name_list[0]!r} wasn't offered via "
                    f"in ClientHello: {self.config.alpn}")
                raise alerts.IllegalParameter(e)

        # Heartbeat
        server_hb = server_extensions.get(ExtensionType.HEARTBEAT)
        if server_hb:
            nconfig.can_send_heartbeat = (
                self.config.can_send_heartbeat and
                server_hb.mode == HeartbeatMode.PEER_ALLOWED_TO_SEND
            )
            nconfig.can_echo_heartbeat = self.config.can_echo_heartbeat
        else:
            nconfig.can_send_heartbeat = False
            nconfig.can_echo_heartbeat = False

        return shared_key
