from cryptography.hazmat.primitives.asymmetric import dh

from siotls import alerts
from siotls.crypto import ffdhe
from siotls.iana import (
    TLSVersion,
    ContentType,
    HandshakeType,
    NamedGroup,
)
from siotls.handshakes import ClientHello
from siotls.extensions import (
    SupportedVersionsRequest,
    PreSharedKeyRequest, PskKeyExchangeModes,
    SignatureAlgorithms,
    #SignatureAlgorithmsCert,
    SupportedGroups,
    KeyShareRequest, KeyShareEntry,
    ServerNameList, HostName,
    Cookie,
)
from . import State, hello_retry_request_magic


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
    is_encrypted = False

    def initiate_connection(self):

        client_hello = ClientHello(self.random, self.config.cipher_suites, [
            SupportedVersionsRequest([TLSVersion.TLS_1_3]),
        ])

        if self._cookie:
            client_hello.extensions.append(Cookie(self._cookie))

        if self.host_names:
            client_hello.extensions.append(ServerNameList([
                HostName(host_name) for host_name in self.host_names
            ]))

        if self._pre_shared_key:
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

        entries = []
        has_seen_secp = False
        has_seen_x = False
        has_seen_ff = False

        for group in self.config.key_exchanges:
            if NamedGroup.is_secp(group) and not has_seen_secp:
                privkey, key_exchange = self._make_key_exchange_secp(group)
                has_seen_secp = True
            elif NamedGroup.is_x(group) and not has_seen_x:
                privkey, key_exchange = self._make_key_exchange_x(group)
                has_seen_x = True
            elif NamedGroup.is_ff(group) and not has_seen_ff:
                privkey, key_exchange = self._make_key_exchange_ff(group)
                has_seen_ff = True
            else:
                continue
            self._key_exchange_privkeys[group] = privkey
            entries.append(KeyShareEntry(group, key_exchange))

        return entries

    def _make_key_exchange_secp(self, group):
        raise NotImplementedError("todo")

    def _make_key_exchange_x(self, group):
        raise NotImplementedError("todo")

    def _make_key_exchange_ff(self, group):
        p, g, q, p_length, min_key_length = ffdhe.groups[group]
        params = dh.DHParameterNumbers(p, q).parameters()
        privkey = params.generate_private_key()

        y = privkey.public_key().public_numbers().y
        key_exchange = y.to_bytes(p_length, 'big')

        return privkey, key_exchange

class ClientWaitSh(State):
    is_encrypted = False
    can_send_application_data = False

    def process(self, content):
        if content.msg_type != ContentType.HANDSHAKE:
            raise alerts.UnexpectedMessage()
        if content.handshake_type != HandshakeType.SERVER_HELLO:
            raise alerts.UnexpectedMessage()

        if content.random == hello_retry_request_magic:
            self._process_hello_retry_request(content)
        else:
            self._process_server_hello(content)

    def _process_hello_retry_request(self, content):
        raise NotImplementedError("todo")

    def _process_server_hello(self, content):
        raise NotImplementedError("todo")




class ClientWaitEe(State):
    is_encrypted = True
    can_send_application_data = False


class ClientWaitCertCr(State):
    is_encrypted = True
    can_send_application_data = False


class ClientWaitCert(State):
    is_encrypted = True
    can_send_application_data = False


class ClientWaitCv(State):
    is_encrypted = True
    can_send_application_data = False


class ClientWaitFinished(State):
    is_encrypted = True
    can_send_application_data = False


class ClientConnected(State):
    is_encrypted = True
    can_send_application_data = True


class ClientClosed(State):
    is_encrypted = False
    can_send_application_data = False
