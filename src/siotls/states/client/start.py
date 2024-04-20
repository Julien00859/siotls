from siotls.contents.handshakes import ClientHello
from siotls.contents.handshakes.extensions import (
    ALPN,
    ClientCertificateTypeRequest,
    Cookie,
    Heartbeat,
    HostName,
    KeyShareRequest,
    ServerCertificateTypeRequest,
    ServerNameListRequest,
    SignatureAlgorithms,
    SupportedGroups,
    SupportedVersionsRequest,
)
from siotls.crypto.key_share import init as key_share_init
from siotls.iana import HeartbeatMode, TLSVersion

from .. import State
from . import ClientWaitServerHello


class ClientStart(State):
    can_send_application_data = False

    def __init__(self, connection, cookie=None):
        super().__init__(connection)
        self._cookie = cookie
        self._key_shares = {}

    def initiate_connection(self):
        extensions = [
            SupportedVersionsRequest([TLSVersion.TLS_1_3]),
            SignatureAlgorithms(self.config.signature_algorithms),
            SupportedGroups(self.config.key_exchanges),
            Heartbeat(
                HeartbeatMode.PEER_ALLOWED_TO_SEND
                if self.config.can_echo_heartbeat else
                HeartbeatMode.PEER_NOT_ALLOWED_TO_SEND
            ),
        ]
        if self.config.hostnames:
            extensions.append(ServerNameListRequest([
                HostName(hostname) for hostname in self.config.hostnames
            ]))
        if self.config.alpn:
            extensions.append(ALPN(self.config.alpn))
        if self.config.public_key:  # x509 assumed when extension missing
            extensions.append(ClientCertificateTypeRequest(self.config.certificate_types))
        if self.config.trusted_public_keys:  # x509 assumed when extension missing
            extensions.append(ServerCertificateTypeRequest(self.config.peer_certificate_types))
        if self._cookie:
            extensions.append(Cookie(self._cookie))
        extensions.append(KeyShareRequest(self._init_key_share()))

        self._send_content(ClientHello(
            self._client_unique, self.config.cipher_suites, extensions,
        ))
        self._move_to_state(ClientWaitServerHello, key_shares=self._key_shares)

    def _init_key_share(self):
        # We could send a ClientHello without KeyShareRequest, wait for
        # the server to choose one of the key exchange algorithm and
        # only then init the KeyShareRequest with the negociated algo.
        # Actually, there is an important chance that the server will
        # choose either our first Finite Field group or our first
        # Elliptic Curve group. Pre-shoot a KeyShare entry per group
        # family to save a round-trip. At worse we'll just send another
        # in reply to a HelloRetryRequest.

        entries = {}
        has_seen_ecdhe = False
        has_seen_ffdhe = False

        for key_exchange in self.config.key_exchanges:
            if key_exchange.is_ff() and not has_seen_ffdhe:
                has_seen_ffdhe = True
            elif not key_exchange.is_ff() and not has_seen_ecdhe:
                has_seen_ecdhe = True
            else:
                continue

            private_key, my_key_share = key_share_init(key_exchange)
            self._key_shares[key_exchange] = private_key
            entries[key_exchange] = my_key_share

        return entries
