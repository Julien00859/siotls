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
    can_send_application_data = False
    is_encrypted = False


class ServerRecvdCh(State):
    can_send_application_data = False
    is_encrypted = False


class ServerNegotiated(State):
    can_send_application_data = False
    is_encrypted = True


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
