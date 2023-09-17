class State:
    is_encrypted: bool
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

hello_retry_request_magic = bytes.fromhex("""
    CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
    C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
""")

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
