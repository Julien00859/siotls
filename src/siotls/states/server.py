from cryptography.hazmat.primitives.asymmetric import dh
from siotls.iana import (
    ContentType,
    HandshakeType,
    ExtensionType,
    NamedGroup,
    TLSVersion,
)
from siotls.contents import alerts
from siotls.crypto import ffdhe
from . import State

from siotls.contents import ChangeCipherSpec
from siotls.handshakes import (
    HelloRetryRequest,
    ServerHello,
    EncryptedExtensions,
    Certificate,
    CertificateVerify,
    Finished,
)
from siotls.extensions import (
    SupportedVersionsResponse,
    KeyShareResponse, KeyShareRetry
)


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
    is_encrypted = False

    def initiate_connection(self):
        self._move_to_state(ServerWaitCh)


class ServerWaitCh(State):
    can_send_application_data = False
    is_encrypted = False
    _did_send_change_cipher_spec = False

    def process(self, client_hello):
        if client_hello.msg_type != ContentType.HANDSHAKE:
            raise alerts.UnexpectedMessage()
        if client_hello.handshake_type != HandshakeType.CLIENT_HELLO:
            raise alerts.UnexpectedMessage()

        if psk := client_hello.extensions.get(ExtensionType.PRE_SHARED_KEY):
            raise NotImplementedError("todo")

        cipher_suite = self._find_common_cipher_suite(client_hello)
        digital_signature = self._find_common_digital_signature(client_hello)
        key_exchange = (
            self._find_common_key_exchange_via_key_share(client_hello) or
            self._find_common_key_exchange_via_supported_groups(client_hello))
        if not (key_exchange and cipher_suite and digital_signature):
            raise alerts.HandshakeFailure()

        if not self._can_resume_key_share(client_hello, key_exchange):
            self._send_hello_retry_request(cipher_suite, key_exchange)
            return

        clear_extensions, encrypted_extensions, self.nconfig = self._negociate(
            client_hello, cipher_suite, digital_signature, key_exchange)

        self._send_content(ServerHello(
            self.random, self.nconfig.cipher_suite, clear_extensions))

        if not self._did_send_change_cipher_spec:
            self._send_content(ChangeCipherSpec())

        self.is_encrypted = True

        self._send_content(EncryptedExtensions(encrypted_extensions))
        self._send_content(Certificate(...))
        self._send_content(CertificateVerify(...))
        self._send_content(Finished(...))
        self._move_to_state(ServerWaitFlight2)

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

    def _find_common_cipher(self, client_hello):
        for cipher_suite in self.config.cipher_suites:
            if cipher_suite in client_hello.cipher_suites:
                return cipher_suite

    def _find_common_digital_signature(self, client_hello):
        try:
            ext = client_hello.extensions[ExtensionType.SIGNATURE_ALGORITHMS]
        except KeyError as exc:
            raise alerts.MissingExtension() from exc
        for digital_signatures in self.config.key_exchanges:
            if digital_signatures in ext.supported_signature_algorithms:
                return digital_signatures

    def _can_resume_key_share(self, client_hello, key_exchange):
        key_share = client_hello.extensions.get(ExtensionType.KEY_SHARE)
        return key_share and key_exchange in key_share.client_shares

    def _send_hello_retry_request(self, cipher_suite, key_exchange):
        if self._did_send_change_cipher_spec:
            msg = "invalid KeyShare in second ClientHello"
            raise alerts.IllegalParameter(msg)
        self._send_content(HelloRetryRequest(self.random, cipher_suite, [
            SupportedVersionsResponse(TLSVersion.TLS_1_3),
            KeyShareRetry(key_exchange),
        ]))
        self._send_content(ChangeCipherSpec())
        self._did_send_change_cipher_spec = True

    def _resume_key_share(self, key_exchange, peer_key_share_data):
        if not NamedGroup.is_ff(key_exchange):
            raise NotImplementedError("todo")

        p, g, q, p_length, min_key_length = ffdhe.groups[key_exchange]
        if len(peer_key_share_data) < min_key_length:
            raise alerts.InsufficientSecurity()

        pn = dh.DHParameterNumbers(p, q)
        x = int.from_bytes(peer_key_share_data, 'big')
        pubkey = dh.DHPublicNumbers(x, pn).public_key()

        privkey = pn.parameters().generate_private_key()
        y = privkey.public_key().public_numbers().y
        my_key_share_data = y.to_bytes(p_length, 'big')

        shared_secret = privkey.exchange(pubkey)
        return shared_secret, my_key_share_data

    def _negociate(self, client_hello, cipher_suite, digital_signature, key_exchange):
        clear_extensions = [SupportedVersionsResponse(TLSVersion.TLS_1_3)]
        encrypted_extensions = []

        key_share = client_hello.extensions[ExtensionType.KEY_SHARE]
        shared_secret, key_share_data = self._resume_key_share(
            key_exchange, key_share.client_shares[key_exchange])
        clear_extensions.append(KeyShareResponse(key_exchange, key_share_data))

        from siotls.connection import TLSNegociation  # noqa
        return clear_extensions, encrypted_extensions, TLSNegociation(
            cipher_suite=cipher_suite,
            digital_signature=digital_signature,
            key_exchange=key_exchange,
            shared_secret=shared_secret,
        )

class ServerWaitEoed(State):
    can_send_application_data = True
    is_encrypted = True


class ServerWaitFlight2(State):
    can_send_application_data = True
    is_encrypted = True


class ServerWaitCert(State):
    can_send_application_data = True
    is_encrypted = True


class ServerWaitCv(State):
    can_send_application_data = True
    is_encrypted = True


class ServerWaitFinished(State):
    can_send_application_data = True
    is_encrypted = True


class ServerConnected(State):
    can_send_application_data = True
    is_encrypted = True


class ServerClosed(State):
    can_send_application_data = True
    is_encrypted = False
