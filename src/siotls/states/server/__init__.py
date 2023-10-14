r"""
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

# ruff: noqa: F401, E402
# isort: skip_file
from .closed import ServerClosed
from .connected import ServerConnected
from .wait_finished import ServerWaitFinished
from .wait_certificate_verify import ServerWaitCertificateVerify
from .wait_certificate import ServerWaitCertificate
from .wait_flight2 import ServerWaitFlight2
from .wait_end_of_early_data import ServerWaitEndOfEarlyData
from .wait_client_hello import ServerWaitClientHello
from .start import ServerStart
