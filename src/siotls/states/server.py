from types import SimpleNamespace

from siotls.crypto.key_share import resume as key_share_resume
from siotls.iana import (
    ContentType,
    HandshakeType,
    ExtensionType,
    TLSVersion,
)
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
    KeyShareResponse, KeyShareRetry
)
from . import State


server_sm = r"""
                              START <-----+
               Recv ClientHello |         | Send HelloRetryRequest
                                v         |
                              WAIT_CH ----+
                                | Select parameters
                                v
                             NEGOTIATED
                                | Send ServerHello
                                | K_send = handshake
                                | Send EncryptedExtensions
                                | [Send CertificateRequest]
 Can send                       | [Send Certificate + CertificateVerify]
 app data                       | Send Finished
 after   -->                    | K_send = application
 here                  +--------+--------+
              No 0-RTT |                 | 0-RTT
                       |                 |
   K_recv = handshake  |                 | K_recv = early data
 [Skip decrypt errors] |    +------> WAIT_EOED -+
                       |    |       Recv |      | Recv EndOfEarlyData
                       |    | early data |      | K_recv = handshake
                       |    +------------+      |
                       |                        |
                       +> WAIT_FLIGHT2 <--------+
                                |
                       +--------+--------+
               No auth |                 | Client auth
                       |                 |
                       |                 v
                       |             WAIT_CERT
                       |        Recv |       | Recv Certificate
                       |       empty |       v
                       | Certificate |    WAIT_CV
                       |             |       | Recv
                       |             v       | CertificateVerify
                       +-> WAIT_FINISHED <---+
                                | Recv Finished
                                | K_recv = application
                                v
                            CONNECTED
"""


class ServerStart(State):
    can_send_application_data = False

    def initiate_connection(self):
        self._move_to_state(ServerWaitCh)


class ServerWaitCh(State):
    can_send_application_data = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._is_first_client_hello = True

    def process(self, client_hello):
        from siotls.connection import TLSNegociatedConfiguration  # noqa

        if client_hello.content_type != ContentType.HANDSHAKE:
            raise alerts.UnexpectedMessage()
        if client_hello.msg_type != HandshakeType.CLIENT_HELLO:
            raise alerts.UnexpectedMessage()

        if psk := client_hello.extensions.get(ExtensionType.PRE_SHARED_KEY):  # noqa: F841
            raise NotImplementedError("todo")

        nconfig = SimpleNamespace()
        self._negociate_algorithms(client_hello, nconfig)

        if self._is_first_client_hello:
            self._setup_transcript_hash(nconfig.cipher_suite.digest)

        if not self._can_resume_key_share(client_hello, nconfig.key_exchange):
            self._send_hello_retry_request()
            return

        clear_extensions, encrypted_extensions = (
            self._negociate_extensions(client_hello.extensions, nconfig))

        key_share_response = self._resume_key_share(
            client_hello.extensions[ExtensionType.KEY_SHARE],
            nconfig.key_exchange
        )
        clear_extensions.append(key_share_response)

        self._send_content(ServerHello(
            self._nonce, nconfig.cipher_suite, clear_extensions))

        if self._is_first_client_hello:
            self._send_content(ChangeCipherSpec())

        self.nconfig = TLSNegociatedConfiguration(**vars(nconfig))

        return  # temporary
        self._send_content(EncryptedExtensions(encrypted_extensions))
        self._send_content(Certificate(...))
        self._send_content(CertificateVerify(...))
        self._send_content(Finished(...))
        self._move_to_state(ServerWaitFlight2)

    def _negociate_algorithms(self, client_hello, nconfig):
        cipher_suite = self._find_common_cipher_suite(client_hello)
        if not cipher_suite:
            msg = "no common cipher suite found"
            raise alerts.HandshakeFailure(msg)

        digital_signature = self._find_common_digital_signature(client_hello)
        if not digital_signature:
            msg = "no common digital signature found"
            raise alerts.HandshakeFailure(msg)

        key_exchange = (
            self._find_common_key_exchange_via_key_share(client_hello) or
            self._find_common_key_exchange_via_supported_groups(client_hello))
        if not key_exchange:
            msg = "no common key exchange found"
            raise alerts.HandshakeFailure(msg)

        nconfig.cipher_suite = cipher_suite
        nconfig.digital_signature = digital_signature
        nconfig.key_exchange = key_exchange

    def _find_common_key_exchange_via_key_share(self, client_hello):
        key_share = client_hello.extensions.get(ExtensionType.KEY_SHARE)
        if not key_share:
            return
        for group in self.config.key_exchanges:
            if group in key_share.client_shares:
                return group

    def _find_common_key_exchange_via_supported_groups(self, client_hello):
        try:
            supported_groups = client_hello.extensions[ExtensionType.KEY_SHARE]
        except KeyError as exc:
            raise alerts.MissingExtension() from exc
        for group in self.config.key_exchanges:
            if group in supported_groups.named_group_list:
                return group

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

    def _can_resume_key_share(self, client_hello, key_exchange):
        key_share = client_hello.extensions.get(ExtensionType.KEY_SHARE)
        return key_share and key_exchange in key_share.client_shares

    def _send_hello_retry_request(self, cipher_suite, key_exchange):
        if not self._is_first_client_hello:
            msg = "invalid KeyShare in second ClientHello"
            raise alerts.IllegalParameter(msg)
        self._send_content(
            HelloRetryRequest(self._nonce, cipher_suite, [
                SupportedVersionsResponse(TLSVersion.TLS_1_3),
                KeyShareRetry(key_exchange),
            ])
        )
        self._send_content(ChangeCipherSpec())
        self._is_first_client_hello = False

    def _negociate_extensions(self, client_extensions, nconfig):
        clear_extensions = [SupportedVersionsResponse(TLSVersion.TLS_1_3)]
        encrypted_extensions = []

        if mfl := client_extensions.get(ExtensionType.MAX_FRAGMENT_LENGTH):
            nconfig.max_fragment_length = mfl.max_fragment_length
            clear_extensions.append(mfl)  # echo back to acknoledge

        return clear_extensions, encrypted_extensions

    def _resume_key_share(self, key_share, key_exchange):
        peer_key_share = key_share.client_shares[key_exchange]
        self.secrets.key_share, my_key_share = key_share_resume(
            key_exchange, peer_key_share)
        return KeyShareResponse(key_exchange, my_key_share)

class ServerWaitEoed(State):
    can_send_application_data = True


class ServerWaitFlight2(State):
    can_send_application_data = True


class ServerWaitCert(State):
    can_send_application_data = True


class ServerWaitCv(State):
    can_send_application_data = True


class ServerWaitFinished(State):
    can_send_application_data = True


class ServerConnected(State):
    can_send_application_data = True


class ServerClosed(State):
    can_send_application_data = True
