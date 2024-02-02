class State:
    can_send_application_data: bool

    def __init__(self, connection):
        object.__setattr__(self, 'connection', connection)

    def __getattr__(self, name):
        if hasattr(self.connection, name):
            return getattr(self.connection, name)
        return object.__getattribute__(self, name)

    def __setattr__(self, name, value):
        return setattr(self.connection, name, value)

    def initiate_connection(self):
        e = "cannot initiate connection in this state"
        raise NotImplementedError(e)

    def process(self, content):  # noqa: ARG002
        e = "cannot process content in this state"
        raise NotImplementedError(e)


from .client import (
    ClientClosed,
    ClientConnected,
    ClientStart,
    ClientWaitCertCr,
    ClientWaitCertificate,
    ClientWaitCertificateVerify,
    ClientWaitEncryptedExtensions,
    ClientWaitFinished,
    ClientWaitServerHello,
)
from .server import (
    ServerClosed,
    ServerConnected,
    ServerStart,
    ServerWaitCertificate,
    ServerWaitCertificateVerify,
    ServerWaitClientHello,
    ServerWaitEndOfEarlyData,
    ServerWaitFinished,
    ServerWaitFlight2,
)
