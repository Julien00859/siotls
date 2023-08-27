import textwrap
from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody
from . import Extension


class Cookie(Extension, SerializableBody):
    extension_type = ExtensionType.COOKIE
    _handshake_types = {HT.CLIENT_HELLO}

    _struct = textwrap.dedent("""\
        struct {
            opaque cookie<1..2^16-1>;
        } Cookie;
    """).strip()
    cookie: bytes

    def __init__(self, cookie):
        self.cookie = cookie

    @classmethod
    def parse_body(cls, stream):
        cookie = stream.read_var(2)
        return cls(cookie)

    def serialize_body(self):
        return b''.join([
            len(self.cookie).to_bytes(2, 'big'),
            self.cookie,
        ])
