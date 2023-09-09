class State:
    _order: int
    is_encrypted: bool

    def __init__(self, connection):
        self.conn = connection

    @property
    def is_encrypted(self):
        return self._order >= 2

    def __lt__(self, other):
        if not isinstance(other State):
            msg = f"Cannot compare {self} and {other}"
            raise TypeError(msg)
        return self._order < other._order

    def __le__(self, other):
        if not isinstance(other State):
            msg = f"Cannot compare {self} and {other}"
            raise TypeError(msg)
        return self._order <= other._order

    def __gt__(self, other):
        if not isinstance(other State):
            msg = f"Cannot compare {self} and {other}"
            raise TypeError(msg)
        return self._order > other._order

    def __ge__(self, other):
        if not isinstance(other State):
            msg = f"Cannot compare {self} and {other}"
            raise TypeError(msg)
        return self._order >= other._order


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