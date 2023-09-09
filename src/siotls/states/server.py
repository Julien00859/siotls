from . import State


server_sm = r"""
                              START <-----+
               Recv ClientHello |         | Send HelloRetryRequest
                                v         |
                             RECVD_CH ----+
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
    _order = 0
    is_encrypted = False

class ServerRecvdCh(State):
    _order = 1
    is_encrypted = False

class ServerNegotiated(State):
    _order = 2
    is_encrypted = True

class ServerWaitEoed(State):
    _order = 3
    is_encrypted = True

class ServerWaitFlight2(State):
    _order = 4
    is_encrypted = True

class ServerWaitCert(State):
    _order = 5
    is_encrypted = True

class ServerWaitCv(State):
    _order = 6
    is_encrypted = True

class ServerWaitFinished(State):
    _order = 7
    is_encrypted = True

class ServerConnected(State):
    _order = 8
    is_encrypted = True
