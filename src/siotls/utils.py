import abc
import binascii
import itertools
import math
import time
from datetime import datetime
from http import HTTPStatus
from wsgiref.handlers import format_date_time

import siotls

_sentinel = object()


class RegistryMeta(abc.ABCMeta):
    def __getitem__(cls, entry):
        return cls._registry[entry]


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

HTTP11_REQUEST = f"""\
{{method}} {{path}} HTTP/1.1\r
Host: {{host}}\r
User-Agent: siotls/{siotls.__version__}\r
Connection: close\r
Content-Type: text/plain; charset=utf-8\r
Content-Length: {{length}}\r
\r
{{body}}"""

def make_http11_request(host: str, method: str, path: str, body: str):
    return HTTP11_REQUEST.format(
        host=host,
        method=method,
        path=path,
        length=len(body),
        body=body
    )

HTTP11_RESPONSE = f"""\
HTTP/1.1 {{status.value}} {{status.phrase}}\r
Date: {{date}}\r
Server: siotls/{siotls.__version__}\r
Connection: close\r
Content-Type: text/plain; charset=utf-8\r
Content-Length: {{length}}\r
\r
{{body}}"""

def make_http11_response(code: int, body: str, now: datetime | None = None):
    return HTTP11_RESPONSE.format(
        status=HTTPStatus(code),
        date=format_date_time(now.timestamp() if now else time.time()),
        length=len(body),
        body=body,
    )


def try_cast(type_, value, exceptions=ValueError):
    try:
        return type_(value)
    except exceptions:
        return value


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


def submap(mapping, keys):
    keys = frozenset(keys)
    return {key: mapping[key] for key in mapping if key in keys}
