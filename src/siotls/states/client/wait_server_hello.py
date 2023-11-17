from siotls.contents import alerts, ChangeCipherSpec
from siotls.iana import (
    ContentType,
    HandshakeType,
    HandshakeType_,
    ExtensionType
)
from .. import State


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
        self._server_nonce = server_hello.random

        self._transcript_hash.update(self._last_server_hello)
        self._last_server_hello = None
        raise NotImplementedError("todo")
