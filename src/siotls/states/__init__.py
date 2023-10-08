class State:
    can_send_application_data: bool

    def __init__(self, connection):
        object.__setattr__(self, 'connection', connection)

    def __getattr__(self, name):
        if hasattr(self.connection, name):
            return getattr(self.connection, name)
        return object.__getattr__(self, name)

    def __setattr__(self, name, value):
        return setattr(self.connection, name, value)

    def initiate_connection(self):
        raise NotImplementedError("cannot initiate connection in this state")

    def process(self, content):
        raise NotImplementedError("cannot process content in this state")


# ruff: noqa: F401, E402
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
    ServerWaitCh,
    ServerWaitEoed,
    ServerWaitFlight2,
    ServerWaitCert,
    ServerWaitCv,
    ServerWaitFinished,
    ServerConnected,
)
