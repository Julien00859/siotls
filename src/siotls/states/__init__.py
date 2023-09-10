class State:
    is_encrypted: bool
    can_send_application_data: bool

    def __init__(self, connection):
        self.connection = connection

    def __getattr__(self, name):
        return getattr(self.connection, name)

    def initiate_connection(self):
        raise NotImplementedError("cannot initiate connection in this state")

    def process(self, content):
        raise NotImplementedError("cannot process content in this state")


# ruff: isort: off
from .client import (
    ClientStart,
    ClientWaitSh,
    ClientWaitEe,
    ClientWaitCertCr,
    ClientWaitCert,
    ClientWaitCv,
    ClientWaitFinished,
    ClientConnected,
)

from .server import (
    ServerStart,
    ServerRecvdCh,
    ServerNegotiated,
    ServerWaitEoed,
    ServerWaitFlight2,
    ServerWaitCert,
    ServerWaitCv,
    ServerWaitFinished,
    ServerConnected,
)
