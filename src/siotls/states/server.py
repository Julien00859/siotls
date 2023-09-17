from cryptography.hazmat.primitives.asymmetric import dh
from siotls.iana import (
    ContentType,
    HandshakeType,
    ExtensionType,
    NamedGroup,
)
from siotls.contents import alerts
from siotls.crypto import ffdhe
from . import State

from siotls.contents import ChangeCipherSpec
from siotls.handshakes import ServerHello, HelloRetryRequest
from siotls.extensions import KeyShareResponse, empty_key_share_request


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
    did_send_change_cipher_spec = False

    def process(self, content):
        if content.msg_type != ContentType.HANDSHAKE:
            raise alerts.UnexpectedMessage()
        if content.handshake_type != HandshakeType.CLIENT_HELLO:
            raise alerts.UnexpectedMessage()

        if psk := content.extensions.get(ExtensionType.PRE_SHARED_KEY):
            raise NotImplementedError("todo")

        # Find the common key exchange (like DH), cipher (like AES) and
        # digital signature (like RSA/Ed25519)
        common_key_exchange = (
            self._find_common_key_exchange_via_key_share(content) or
            self._find_common_key_exchange_via_supported_groups(content)
        )
        if not common_key_exchange:
            raise alerts.HandshakeFailure()

        common_cipher_suite = self._find_common_cipher_suite(content)
        if not common_cipher_suite:
            raise alerts.HandshakeFailure()

        common_digital_signature = self._find_common_digital_signature(content)
        if not common_digital_signature:
            raise alerts.HandshakeFailure()

        # The client can pre-shoot a few KeyShare (material for the key
        # exchange) for all or a subset of the offered supported groups.
        # In case he didn't sent any, or that he didn't pre-shoot a
        # KeyShare for the supported group that we actually selected,
        # then ask the client to repeat the handshake: this time with a
        # KeyShare containing the supported group that we selected.
        peer_key_exchange = content.extensions.get(
            ExtensionType.KEY_SHARE, empty_key_share_request
        ).client_shares.get(common_key_exchange)
        if not peer_key_exchange:
            hello_retry_request = self._make_hello_retry_request()
            self._send_content(hello_retry_request)
            if not self.did_send_change_cipher_spec:
                self._send_content(ChangeCipherSpec())
                self.did_send_change_cipher_spec = True
            return

        server_hello = ServerHello(self.random, common_cipher_suite)
        shared_secret, my_key_exchange = self._resume_key_share(
            common_key_exchange, peer_key_exchange)

        KeyShareResponse(common_key_exchange, my_key_exchange)

    def _find_common_key_exchange_via_key_share(self, content):
        key_share = content.extensions.get(ExtensionType.KEY_SHARE)
        if not key_share:
            return
        for group in self.config.key_exchanges:
            if group in key_share.client_shares:
                return group

    def _find_common_key_exchange_via_supported_groups(self, content):
        try:
            supported_groups = content.extensions[ExtensionType.KEY_SHARE]
        except KeyError as exc:
            raise alerts.MissingExtension() from exc
        for group in self.config.key_exchanges:
            if group in supported_groups.named_group_list:
                return group

    def _find_common_cipher(self, content):
        for cipher_suite in self.config.cipher_suites:
            if cipher_suite in content.cipher_suites:
                return cipher_suite

    def _find_common_digital_signature(self, content):
        try:
            ext = content.extensions[ExtensionType.SIGNATURE_ALGORITHMS]
        except KeyError as exc:
            raise alerts.MissingExtension() from exc
        for digital_signatures in self.config.key_exchanges:
            if digital_signatures in ext.supported_signature_algorithms:
                return digital_signatures

    def _resume_key_share(self, named_group, client_key_exchange):
        if not NamedGroup.is_ff(named_group):
            raise NotImplementedError("todo")

        p, g, q, p_length, min_key_length = ffdhe.groups[named_group]
        if len(client_key_exchange) < min_key_length:
            raise alerts.InsufficientSecurity()

        pn = dh.DHParameterNumbers(p, q)
        x = int.from_bytes(client_key_exchange, 'big')
        pubkey = dh.DHPublicNumbers(x, pn).public_key()

        privkey = pn.parameters().generate_private_key()
        y = privkey.public_key().public_numbers().y
        key_exchange = y.to_bytes(p_length, 'big')

        shared_secret = privkey.exchange(pubkey)
        return shared_secret, key_exchange


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
