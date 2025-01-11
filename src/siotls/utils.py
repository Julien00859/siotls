import abc
import binascii
import itertools
import math
import re

from number import Number

_sentinel = object()


class RegistryMeta(abc.ABCMeta):
    def __getitem__(cls, entry):
        return getattr(cls, cls._registry_key)[entry]


class intbyte(int):  # noqa: N801
    """
    Integer with a Byte SI representation

    >>> Byte(0)
    0
    >>> Byte(2)
    2
    >>> Byte('65')
    65
    >>> Byte('89B')
    89
    >>> Byte('1k')
    1000
    >>> Byte('1ki')
    1024
    >>> Byte('1.5k')
    1500
    >>> Byte('1.5ki')
    1536
    >>> Byte('1ki') + Byte('-1k')
    24
    >>> str(Byte(0))
    '0'
    >>> str(Byte('70M'))
    '70MB'
    >>> str(Byte('43Mi'))
    '43MiB'
    >>> str(Byte('1.5M'))
    '1500kB'
    """

    __sizes = {  # noqa: RUF012
        'Ti': 1 << 40,
        'T': 1000 ** 4,
        'Gi': 1 << 30,
        'G': 1000 ** 3,
        'Mi': 1 << 20,
        'M': 1000 ** 2,
        'ki': 1 << 10,
        'k': 1000 ** 1,
        '':  1,
    }

    __re = re.compile(r"""^
        (?P<float>[-+]?(\d+(\.\d*)?|\.\d+)([eE][-+]?\d+)?)  # The number as float
        (?P<unit>k|M|G|T|ki|Mi|Gi|Ti)?[Bo]?                 # The unit
    $""", re.VERBOSE)

    def __new__(cls, x=0):
        if isinstance(x, Number):
            return super().__new__(cls, x)

        match = cls.__re.search(x)
        if not match:
            e = f"not a valid {cls.__name__} representation: {x}"
            raise ValueError(e)
        base = float(match.group('float'))
        unit = cls.__sizes[match.group('unit') or '']
        return super().__new__(cls, base * unit)

    def __str__(self):
        if not self:
            return "0"
        for unit, size in type(self).__sizes.items():  # noqa: SLF001
            d, m = divmod(self, size)
            if not m:
                return f"{d}{unit}B"
        return super().__str__()



def hexdump(bytes_):
    r"""
    Produce a pretty hexdump suitable for human reading.

    >>> print(hexdump(b'\x00\x17Hello world!\nSweat day.\x00'))
    0000: 00 17 48 65 6c 6c 6f 20  77 6f 72 6c 64 21 0a 53  0.Hello  world! S
    0010: 77 65 61 74 20 64 61 79  2e 00                    weat day .0
    >>>
    """
    # ruff: noqa: PLR2004
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
        xd.extend([32 if byte in (9, 10, 11, 13) # 32 is ' ', other are blancs
            else byte + 48 if 0 <= byte <= 9     # 48 is '0'
            else byte + 87 if 10 <= byte <= 15   # 87 is 'a'
            else byte if 32 <= byte <= 126       # 32-126 are the ascii printable
            else 46 for byte in line[:8]])       # 46 is '.'
        if len(line) > 8:
            xd.extend(b' ')
        xd.extend([32 if byte in (9, 10, 11, 13) # 32 is ' ', other are blancs
            else byte + 48 if 0 <= byte <= 9     # 48 is '0'
            else byte + 87 if 10 <= byte <= 15   # 87 is 'a'
            else byte if 32 <= byte <= 126       # 32-126 are the ascii printable
            else 46 for byte in line[8:]])       # 46 is '.'
        xd.extend(b'\n')
        i += 16
    if bytes_:
        xd.pop()  # ditch last \n
    return xd.decode()


class peekable:  # noqa: N801
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


def socket_pformat(address, default_port=None):
    addr, port, *_ = address
    if not port or port == default_port:
        return addr
    if ':' in addr[:5]:  # ipv6
        return f'[{addr}]:{port}'
    return f'{addr}:{port}'


def submap(mapping, keys):
    keys = frozenset(keys)
    return {key: mapping[key] for key in mapping if key in keys}


def try_cast(type_, value, exceptions=ValueError):
    try:
        return type_(value)
    except exceptions:
        return value
