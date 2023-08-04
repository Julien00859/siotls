class TLS:
    def __init__(self):
        self._buffer = bytearray()
        self._state =

    def push(self, data):
        self._buffer += data

    def _waiting_n(self):
        return self._status._waiting_n()
