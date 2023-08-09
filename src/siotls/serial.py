import abc
import contextlib
import io
import logging
from .utils import hexdump

logger = logging.getLogger(__name__)


class MissingData(ValueError):
    pass


def serial_verbose(func):
    def wrapped(data):
        try:
            return func(data)
        except Exception as exc:
            if hasattr(exc, 'serializable_verbose_logged'):
                raise
            exc.serializable_verbose_logged = True
            logger.debug(
                "While parsing data for %s:\n%s",
                func.__self__.__name__,
                hexdump(data),
                exc_info=True
            )
            raise
    return wrapped


def raise_not_implemented_error(*args):
    raise NotImplementedError()


class Serializable(metaclass=abc.ABCMeta):
    @abc.abstractclassmethod
    def parse(cls, data):
        raise NotImplementedError("abstract method")

    @abc.abstractmethod
    def serialize(self):
        raise NotImplementedError("abstract method")

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if 'parse' in cls.__dict__:
            cls.parse = serial_verbose(cls.parse)
        else:
            logger.warning("%s is missing a parse method", cls)
            cls.parse = raise_not_implemented_error


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

    @contextlib.contextmanager
    def lookahead(self):
        pos = self.tell()
        try:
            yield
        finally:
            self.seek(pos)
