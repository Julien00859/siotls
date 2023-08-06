import abc
import contextlib
import io
import struct


class Serializable(metaclass=abc.ABCMeta):
    @abc.abstractclassmethod
    def parse(cls, data):
        raise NotImplementedError("abstract method")

    @abc.abstractmethod
    def serialize(self):
        raise NotImplementedError("abstract method")


class MissingData(ValueError):
    pass


class SerialIO(io.BytesIO):
    def read_exactly(self, n, limit=float('+inf')):
        if n > limit:
            raise ValueError(f"Expected {n} bytes but can only read {limit}.")
        data = b''
        while len(data) != n:
            read = self.read(n - len(data))
            if not read:
                raise MissingData(f"Expected {n} bytes but could only read {len(data)}.")
            data += read
        return data

    def read_int(self, n, limit=float('+inf')):
        return int.from_bytes(self.read_exactly(n, limit), 'big')

    def write_int(self, n, i):
        self.write(i.to_bytes(n, 'big'))

    def read_var(self, n, limit=float('+inf')):
        length = self.read_int(n, limit)
        return self.read_exactly(length, limit - n)

    def write_var(self, n, b):
        self.write_int(n, len(b))
        self.write(b)

    @contextlib.context_manager
    def lookahead(self):
        pos = self.tell():
        try:
            yield
        finally:
            self.seek(pos)
