import abc
import contextlib
import io
import logging
from .utils import hexdump

logger = logging.getLogger(__name__)


class MissingData(ValueError):
    pass


class TooMuchData(ValueError):
    pass


def parse_verbose(meth):
    def wrapped(data, **kwargs):
        logger.debug(
            "Parsing %s\nStruct:\n%s\nData:\n%s\n",
            meth.__self__.__name__,
            meth.__self__._struct,
            hexdump(data),
        )
        return wrapped.meth.__func__(wrapped.cls, data, **kwargs)
    wrapped.meth = meth
    wrapped.cls = None  # set by caller
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

            if getattr(cls.parse, '__isabstractmethod__', False):
                pass
            elif 'parse' in cls.__dict__:
                if '_struct' not in cls.__dict__:
                    logger.warning("%s is missing a _struct declaration", cls)
                    cls._struct = ''
                cls.parse = parse_verbose(cls.parse)
                cls.parse.cls = cls
            else:
                cls.parse = parse_verbose(cls.parse.meth)
                cls.parse.cls = cls


            if 'serialize' in cls.__dict__:
                cls.serialize = serialize_verbose(cls.serialize)

    def __repr__(self):
        output = [type(self).__name__, '(']

        for key, value in vars(self).items():
            if key.startswith('_'):
                continue
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

            if getattr(cls.parse_body, '__isabstractmethod__', False):
                pass
            elif 'parse_body' in cls.__dict__:
                if '_struct' not in cls.__dict__:
                    logger.warning("%s is missing a _struct declaration", cls)
                    cls._struct = ''
                cls.parse_body = parse_verbose(cls.parse_body)
                cls.parse_body.cls = cls
            else:
                cls.parse_body = parse_verbose(cls.parse_body.meth)
                cls.parse_body.cls = cls

            if 'serialize_body' in cls.__dict__:
                cls.serialize_body = serialize_verbose(cls.serialize_body)


class SerialIO(io.BytesIO):
    def read(self, n=None, limit=float('+inf')):
        if n is not None and n > limit:
            raise TooMuchData(f"Expected {n} bytes but can only read {limit}.")
        return super().read(n)

    def read_exactly(self, n, limit=float('+inf')):
        data = b''
        while len(data) != n:
            read = self.read(n - len(data), limit=limit - len(data))
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

    def assert_eof(self):
        current_pos = self.tell()
        eof_pos = self.seek(0, 2)
        if remaining := eof_pos - current_pos:
            self.seek(current_pos, 0)
            raise TooMuchData(f"Expected end of stream but {remaining} bytes remain.")
