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
    _order = 0
    is_encrypted = False

class ClientWaitSh(State):
    _order = 1
    is_encrypted = False

class ClientWaitEe(State):
    _order = 2
    is_encrypted = True

class ClientWaitCertCr(State):
    _order = 3
    is_encrypted = True

class ClientWaitCert(State):
    _order = 4
    is_encrypted = True

class ClientWaitCv(State):
    _order = 5
    is_encrypted = True

class ClientWaitFinished(State):
    _order = 6
    is_encrypted = True

class ClientConnected(State):
    _order = 7
    is_encrypted = True