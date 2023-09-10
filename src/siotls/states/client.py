from siotls.iana import TLSVersion
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
    is_encrypted = False

    def initiate_connection(self):
        client_hello = ClientHello(self.random, self.config.cipher_suites, [
            SupportedVersionsRequest([TLSVersion.TLS_1_3]),
        ])

        if not self._pre_shared_key:
            client_hello.extensions.extend([
                SignatureAlgorithms(self.config.digital_signatures),
                SupportedGroups(self.config.key_exchanges),
                KeyShareRequest([KeyShareEntry(...)]),
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

        self._send_content(client_hello)
        self._move_to_state(ClientWaitSh)


class ClientWaitSh(State):
    is_encrypted = False
    can_send_application_data = False


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
