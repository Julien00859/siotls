import abc
import io
import struct

class Serializable(metaclass=abc.ABCMeta):
    @abc.abstractclassmethod
    def parse(cls, data):
        raise NotImplementedError("abstract method")

    @abc.abstractmethod
    def serialize(self):
        raise NotImplementedError("abstract method")


class ProtocolIO(io.BytesIO):
    def read_exactly(self, n):
        data = b''
        while len(data) != n:
            read = self.read(n - len(data))
            if not read:
                ValueError(f"Expected {n} bytes but could only read {len(data)}.")
            data += read
        return data

    def read_int(self, n):
        return int.from_bytes(self.read_exactly(n), 'big')

    def write_int(self, n, i):
        self.write(i.to_bytes(n, 'big'))

    def read_var(self, n):
        return self.read_exactly(self.read_int(n))

    def write_var(self, n, b):
        self.write_int(n, len(b))
        self.write(b)
