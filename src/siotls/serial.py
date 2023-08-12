import abc
import contextlib
import io
import logging
from .utils import hexdump

logger = logging.getLogger(__name__)


class MissingData(ValueError):
    pass


def parse_verbose(func):
    def wrapped(data):
        logger.debug(
            "Parsing %s\nStruct:\n%s\nData:\n%s\n",
            func.__self__.__name__,
            func.__self__._struct,
            hexdump(data),
        )
        return func(data)
    return wrapped


def serialize_verbose(func):
    def wrapped():
        logger.debug(
            "Serializing %s\nStruct:\n%s\nSelf:\n%s\n",
            func.__self__.__name__,
            func.__self__._struct,
            func.__self__,
        )
        return func()
    return wrapped


class Serializable(metaclass=abc.ABCMeta):
    _struct: str

    @abc.abstractclassmethod
    def parse(cls, data):
        raise NotImplementedError("abstract method")

    @abc.abstractmethod
    def serialize(self):
        raise NotImplementedError("abstract method")

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if logger.isEnabledFor(logging.DEBUG):
            if 'parse' in cls.__dict__:
                cls.parse = parse_verbose(cls.parse)
            if 'serialize' in cls.__dict__:
                cls.serialize = serialize_verbose(cls.serialize)
            if '_struct' not in cls.__dict__:
                logger.warning("%s is missing a _struct declaration", cls)
                cls._struct = ''

    def __repr__(self):
        output = [type(self).__name__, '(']

        for key, value in vars(self).items():
            if key.startswith('_'):
                continue
            if isinstance(key, (Serializable, SerializableBody)):
                output.append(type(value).__name__)
                output.append('()')
            else:
                output.append(str(value))
            output.append(',')

        if output[-1] == ',':
            output.pop()
        output.append(')')
        return ''.join(output)


class SerializableBody(metaclass=abc.ABCMeta):
    _struct: str

    @abc.abstractclassmethod
    def parse_body(cls, data):
        raise NotImplementedError("abstract method")

    @abc.abstractmethod
    def serialize_body(self):
        raise NotImplementedError("abstract method")

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if logger.isEnabledFor(logging.DEBUG):
            if 'parse_body' in cls.__dict__:
                cls.parse_body = parse_verbose(cls.parse_body)
            if 'serialize_body' in cls.__dict__:
                cls.serialize_body = serialize_verbose(cls.serialize_body)
            if '_struct' not in cls.__dict__:
                logger.warning("%s is missing a _struct declaration", cls)
                cls._struct = ''

    __repr__ = Serializable.__repr__


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
