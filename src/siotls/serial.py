import abc
import contextlib
import io
import logging

logger = logging.getLogger(__name__)


class SerializationError(ValueError):
    pass


class MissingDataError(SerializationError):
    pass


class TooMuchDataError(SerializationError):
    pass


class Serializable(metaclass=abc.ABCMeta):
    _struct: str

    @abc.abstractclassmethod
    def parse(cls, stream):
        pass

    @abc.abstractmethod
    def serialize(self):
        pass


class SerializableBody(metaclass=abc.ABCMeta):
    _struct: str

    @abc.abstractclassmethod
    def parse_body(cls, stream):
        pass

    @abc.abstractmethod
    def serialize_body(self):
        pass


class SerialIO(io.BytesIO):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._limits = [float('+inf')]

    def read(self, n=None):
        max_n = self._limits[-1] - self.tell()
        if n is None:
            if len(self._limits) > 1:
                n = max_n
        elif n > max_n:
            e = f"expected {n} bytes but can only read {max_n}"
            raise TooMuchDataError(e)
        return super().read(n)

    def read_exactly(self, n):
        data = b''
        while len(data) != n:
            read = self.read(n - len(data))
            if not read:
                e = f"expected {n} bytes but could only read {len(data)}"
                raise MissingDataError(e)
            data += read
        return data

    def read_int(self, n):
        return int.from_bytes(self.read_exactly(n), 'big')

    def write_int(self, n, i):
        self.write(i.to_bytes(n, 'big'))

    def read_var(self, n):
        length = self.read_int(n)
        return self.read_exactly(length)

    def write_var(self, n, b):
        self.write_int(n, len(b))
        self.write(b)

    def read_listint(self, nlist, nitem):
        length = self.read_int(nlist)
        if length % nitem != 0:
            e =(f"cannot read {length // nitem + 1} uint{nitem * 8}_t out of "
                f"{length} bytes")
            raise SerializationError(e)

        it = iter(self.read_exactly(length))
        return [
            int.from_bytes(bytes(group), 'big')
            for group in zip(*([it] * nitem), strict=True)
        ]

    def write_listin(self, nlist, nitem, items):
        self.write_int(nlist, len(items) * nitem)
        for item in items:
            self.write_int(nitem, item)

    def read_listvar(self, nlist, nitem):
        items = []
        list_stream = type(self)(self.read_var(nlist))
        while not list_stream.is_eof():
            items.append(list_stream.read_var(nitem))
        return items

    def write_listvar(self, nlist, nitem, items):
        prepos = self.tell()
        self.write_int(nlist, 0)  # placeholder
        for item in items:
            self.write_var(nitem, item)
        postpos = self.tell()
        # write the effective size on the placeholder
        self.seek(prepos, 0)
        self.write_int(nlist, postpos - prepos - nlist)
        self.seek(postpos, 0)


    @contextlib.contextmanager
    def lookahead(self):
        pos = self.tell()
        try:
            yield
        finally:
            self.seek(pos)

    def is_eof(self):
        current_pos = self.tell()
        eof_pos = self.seek(0, 2)
        self.seek(current_pos, 0)
        return current_pos == eof_pos

    def assert_eof(self):
        current_pos = self.tell()
        eof_pos = self.seek(0, 2)
        if remaining := eof_pos - current_pos:
            self.seek(current_pos, 0)
            e = f"expected end of stream but {remaining} bytes remain"
            raise TooMuchDataError(e)

    @contextlib.contextmanager
    def limit(self, length):
        new_limit = self.tell() + length
        if new_limit > self._limits[-1]:
            e = "a more restrictive limit is present already"
            raise ValueError(e)

        self._limits.append(new_limit)

        yield

        if self._limits.pop() != new_limit:
            e = "another limit was pop"
            raise RuntimeError(e)
        if not self._limits:
            e = "+inf was pop"
            raise RuntimeError(e)
        if (remaining := new_limit - self.tell()):
            e = f"expected end of chunk but {remaining} bytes remain"
            raise TooMuchDataError(e)
