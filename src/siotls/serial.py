import abc
import contextlib
import io
import logging
from .utils import hexdump

logger = logging.getLogger(__name__)


class SerializationError(ValueError):
    pass


class MissingData(SerializationError):
    pass


class TooMuchData(SerializationError):
    pass


def parse_verbose(meth):
    def wrapped(stream, **kwargs):
        with stream.lookahead():
            data = stream.read()
        logger.debug(
            "Parsing %s\nStruct:\n%s\nData:\n%s\n",
            meth.__self__.__name__,
            meth.__self__._struct,
            hexdump(data),
        )
        return wrapped.meth.__func__(wrapped.cls, stream, **kwargs)
    wrapped.meth = meth
    wrapped.cls = None  # set by caller
    return wrapped


def serialize_verbose(func):
    def wrapped(self):
        data = func(self)
        logger.debug(
            "Serializing %s\nStruct:\n%s\nSelf:\n%s\nData:\n%s\n",
            type(self).__name__,
            self._struct,
            self,
            hexdump(data),
        )
        return data
    return wrapped


class Serializable(metaclass=abc.ABCMeta):
    _struct: str

    @abc.abstractclassmethod
    def parse(cls, stream):
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


class SerializableBody(metaclass=abc.ABCMeta):
    _struct: str

    @abc.abstractclassmethod
    def parse_body(cls, stream):
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
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._limits = [float('+inf')]

    def read(self, n=None):
        max_n = self._limits[-1] - self.tell()
        if n is None:
            if len(self._limits) > 1:
                n = max_n
        elif n > max_n:
            msg = f"Expected {n} bytes but can only read {max_n}."
            raise TooMuchData(msg)
        return super().read(n)

    def read_exactly(self, n):
        data = b''
        while len(data) != n:
            read = self.read(n - len(data))
            if not read:
                msg = f"Expected {n} bytes but could only read {len(data)}."
                raise MissingData(msg)
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
            msg = (f"Cannot read {length // nitem + 1} "
                   f"uint{nitem * 8}_t out of {length} bytes.")
            raise SerializationError(msg)

        it = iter(self.read_exactly(length))
        return [
            int.from_bytes(bytes(group), 'big')
            for group in zip(*([it] * nitem))
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
            msg = f"Expected end of stream but {remaining} bytes remain."
            raise TooMuchData(msg)

    @contextlib.contextmanager
    def limit(self, length):
        new_limit = self.tell() + length
        if new_limit > self._limits[-1]:
            msg = "An more restrictive limit is present already"
            raise ValueError(msg)

        self._limits.append(new_limit)
        try:
            yield
        except:
            raise
        else:
            assert self._limits.pop() == new_limit, "another limit was pop"
            assert self._limits, "+inf was pop"
            if (remaining := new_limit - self.tell()):
                msg = f"Expected end of chunk but {remaining} bytes remain."
                raise TooMuchData(msg)
