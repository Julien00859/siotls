from siotls.contents import alerts
from siotls.crypto.key_share import init as key_share_init
from siotls.iana import (
    TLSVersion,
    ContentType,
    HandshakeType,
)
from siotls.contents.handshakes import ClientHello, HelloRetryRequest
from siotls.contents.handshakes.extensions import (
    SupportedVersionsRequest,
    PreSharedKeyRequest, PskKeyExchangeModes,
    SignatureAlgorithms,
    #SignatureAlgorithmsCert,
    SupportedGroups,
    KeyShareRequest,
    ServerNameList, HostName,
    Cookie,
)
from . import State


client_sm = r"""
                              START <----+
               Send ClientHello |        | Recv HelloRetryRequest
          [K_send = early data] |        |
                                v        |
           /                 WAIT_SH ----+
           |                    | Recv ServerHello
           |                    | K_recv = handshake
       Can |                    v
      send |                 WAIT_EE
     early |                    | Recv EncryptedExtensions
      data |           +--------+--------+
           |     Using |                 | Using certificate
           |       PSK |                 v
           |           |            WAIT_CERT_CR
           |           |        Recv |       | Recv CertificateRequest
           |           | Certificate |       v
           |           |             |    WAIT_CERT
           |           |             |       | Recv Certificate
           |           |             v       v
           |           |              WAIT_CV
           |           |                 | Recv CertificateVerify
           |           +> WAIT_FINISHED <+
           |                  | Recv Finished
           \                  | [Send EndOfEarlyData]
                              | K_send = handshake
                              | [Send Certificate [+ CertificateVerify]]
    Can send                  | Send Finished
    app data   -->            | K_send = K_recv = application
    after here                v
                          CONNECTED
"""


class ClientStart(State):
    def initiate_connection(self):

        client_hello = ClientHello(
            self._nonce,
            self.config.cipher_suites, [
                SupportedVersionsRequest([TLSVersion.TLS_1_3]),
            ]
        )

        if self._cookie:
            client_hello.extensions.append(Cookie(self._cookie))

        if self.config.hostnames:
            client_hello.extensions.append(ServerNameList([
                HostName(hostname) for hostname in self.hostnames
            ]))

        if self.secrets.pre_shared_key:
            raise NotImplementedError("todo")
            client_hello.extensions.extend([
                PskKeyExchangeModes(...),
                PreSharedKeyRequest(...),  # this must be the last extension
            ])
        else:
            key_share_entries = self._init_key_share()
            client_hello.extensions.extend([
                SignatureAlgorithms(self.config.digital_signatures),
                SupportedGroups(self.config.key_exchanges),
                KeyShareRequest(key_share_entries),
            ])

        self._send_content(client_hello)
        self._move_to_state(ClientWaitSh)

    def _init_key_share(self):
        # We could send a ClientHello without KeyShareRequest and wait
        # that the server choose one of the key exchange algorithm and
        # only then init the KeyShareRequest with the negociated algo
        # but there is an important chance that the server will choose
        # either our first Finite Field group or our first Elliptic
        # Curve group. Pre-shoot a KeyShare entry per group family to
        # save a round-trip. At worse we'll just send another in reply
        # to a HelloRetryRequest.

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
            self._key_exchange_privkeys[key_exchange] = private_key
            entries[key_exchange] = my_key_share

        return entries



class ClientWaitSh(State):
    can_send_application_data = False

    def process(self, content):
        if content.content_type != ContentType.HANDSHAKE:
            raise alerts.UnexpectedMessage()
        if content.msg_type != HandshakeType.SERVER_HELLO:
            raise alerts.UnexpectedMessage()

        if content.random == HelloRetryRequest.random:
            self._process_hello_retry_request(content)
        else:
            self._process_server_hello(content)

    def _process_hello_retry_request(self, content):
        raise NotImplementedError("todo")

    def _process_server_hello(self, content):
        raise NotImplementedError("todo")




class ClientWaitEe(State):
    can_send_application_data = False


class ClientWaitCertCr(State):
    can_send_application_data = False


class ClientWaitCert(State):
    can_send_application_data = False


class ClientWaitCv(State):
    can_send_application_data = False


class ClientWaitFinished(State):
    can_send_application_data = False


class ClientConnected(State):
    can_send_application_data = True


class ClientClosed(State):
    can_send_application_data = False
