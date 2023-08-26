import textwrap
from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody
from . import Extension


class Padding(Extension, SerializableBody):
    extension_type = ExtensionType.PADDING
    _handshake_types = {HT.CLIENT_HELLO}

    _struct = textwrap.dedent("""
        struct {
            opaque zeros[Extension.extension_length];
        } PaddingExtension;
    """).strip()
    zeros: bytes

    def __init__(self, zeros):
        self.zeros = zeros

    @classmethod
    def parse_body(cls, data):
        return cls(data)

    def serialize_body(self):
        return self.zeros
