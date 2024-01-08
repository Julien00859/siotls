import binascii
import itertools
import math

_sentinel = object()


def hexdump(bytes_):
    """
    Produce a pretty hexdump suitable for human reading

    >>> hexdump(b'\x00\x17Hello world!\nSweat day.\x00')
    '''\
    0000: 00 17 48 65 6c 6c 6f 20  77 6f 72 6c 64 21 0a 53  ..Hello  world!.S
    0010: 77 65 61 74 20 64 61 79  2e 00                    weat day ..'''
    """
    it = iter(bytes_)
    xd = bytearray()
    hex_ = bytearray()
    d = math.ceil(math.ceil(len(bytes_).bit_length() / 4) / 4) * 4
    i = 0
    while line := bytes(itertools.islice(it, 16)):
        hex_.clear()
        hex_.extend(binascii.hexlify(line[:8], ' '))
        hex_.extend(b'  ')
        hex_.extend(binascii.hexlify(line[8:], ' '))
        hex_.extend(b'  ')
        hex_.extend(b' ' * (50 - len(hex_)))  # 3 * 16 + 2
        xd.extend(f'{i:0{d}x}: '.encode())
        xd.extend(hex_)
        xd.extend([byte + 48 if 0 <= byte <= 9
            else byte + 87 if 10 <= byte <= 15
            else byte if 32 <= byte <= 126
            else 46 for byte in line[:8]])
        xd.extend(b' ')
        xd.extend([byte + 48 if 0 <= byte <= 9
            else byte + 87 if 10 <= byte <= 15
            else byte if 32 <= byte <= 126
            else 46 for byte in line[8:]])
        xd.extend(b'\n')
        i += 16
    if bytes_:
        xd.pop()  # ditch last \n
    return xd.decode()


def try_cast(type_, value, exceptions=ValueError):
    try:
        return type_(value)
    except exceptions:
        return value


def is_string(proto):
    try:
        proto.decode()
    except UnicodeDecodeError:
        return False
    return True


class peekable:
    def __init__(self, iterable):
        self._it = iter(iterable)
        self._peeked = _sentinel

    def __iter__(self):
        return self

    def __next__(self):
        if self._peeked is not _sentinel:
            peeked = self._peeked
            self._peeked = _sentinel
            return peeked
        return next(self._it)

    def peek(self, default=_sentinel):
        if self._peeked is _sentinel:
            try:
                self._peeked = next(self._it)
            except StopIteration:
                if default is _sentinel:
                    raise
                return default
        return self._peeked
