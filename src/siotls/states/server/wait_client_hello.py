from types import SimpleNamespace
from siotls.iana import (
    ContentType,
    HandshakeType,
    ExtensionType,
    TLSVersion,
)
from siotls.contents import alerts, ChangeCipherSpec
from siotls.contents.handshakes import (
    HelloRetryRequest,
)
from siotls.contents.handshakes.extensions import (
    SupportedVersionsResponse,
    KeyShareRetry,
)
from .. import State


class ServerWaitClientHello(State):
    can_send_application_data = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._is_first_client_hello = True

    def process(self, client_hello):
        if client_hello.content_type != ContentType.HANDSHAKE:
            raise alerts.UnexpectedMessage()
        if client_hello.msg_type != HandshakeType.CLIENT_HELLO:
            raise alerts.UnexpectedMessage()

        if _ := client_hello.extensions.get(ExtensionType.PRE_SHARED_KEY):
            raise NotImplementedError("todo")

        nconfig = SimpleNamespace()
        self._negociate_algorithms(client_hello, nconfig)

        if not self._can_resume_key_share(client_hello, nconfig.key_exchange):
            self._send_hello_retry_request(client_hello, nconfig)
            return

        raise NotImplementedError("todo")

    def _negociate_algorithms(self, client_hello, nconfig):
        nconfig.cipher_suite = self._find_common_cipher_suite(client_hello)
        if not nconfig.cipher_suite:
            msg = "no common cipher suite found"
            raise alerts.HandshakeFailure(msg)

        nconfig.digital_signature = self._find_common_digital_signature(client_hello)
        if not nconfig.digital_signature:
            msg = "no common digital signature found"
            raise alerts.HandshakeFailure(msg)

        nconfig.key_exchange = (
            self._find_common_key_exchange_via_key_share(client_hello) or
            self._find_common_key_exchange_via_supported_groups(client_hello))
        if not nconfig.key_exchange:
            msg = "no common key exchange found"
            raise alerts.HandshakeFailure(msg)

    def _find_common_cipher_suite(self, client_hello):
        for cipher_suite in self.config.cipher_suites:
            if cipher_suite in client_hello.cipher_suites:
                return cipher_suite

    def _find_common_digital_signature(self, client_hello):
        try:
            ext = client_hello.extensions[ExtensionType.SIGNATURE_ALGORITHMS]
        except KeyError as exc:
            raise alerts.MissingExtension() from exc
        for digital_signatures in self.config.digital_signatures:
            if digital_signatures in ext.supported_signature_algorithms:
                return digital_signatures

    def _find_common_key_exchange_via_key_share(self, client_hello):
        key_share = client_hello.extensions.get(ExtensionType.KEY_SHARE)
        if not key_share:
            return
        for group in self.config.key_exchanges:
            if group in key_share.client_shares:
                return group

    def _find_common_key_exchange_via_supported_groups(self, client_hello):
        try:
            supported_groups = client_hello.extensions[ExtensionType.SUPPORTED_GROUPS]
        except KeyError as exc:
            raise alerts.MissingExtension() from exc
        for group in self.config.key_exchanges:
            if group in supported_groups.named_group_list:
                return group

    def _can_resume_key_share(self, client_hello, key_exchange):
        key_share = client_hello.extensions.get(ExtensionType.KEY_SHARE)
        return key_share and key_exchange in key_share.client_shares

    def _send_hello_retry_request(self, client_hello, nconfig):
        if not self._is_first_client_hello:
            msg = "invalid KeyShare in second ClientHello"
            raise alerts.IllegalParameter(msg)

        # make sure the client doesn't change its algorithms in between flights
        self.config.cipher_suites = [nconfig.cipher_suite]
        self.config.digital_signatures = [nconfig.digital_signature]
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
        self._send_content(ChangeCipherSpec())
        self._is_first_client_hello = False
