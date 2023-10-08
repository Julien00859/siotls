import textwrap
from dataclasses import dataclass
from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody
from . import Extension


@dataclass(init=False)
class Padding(Extension, SerializableBody):
    extension_type = ExtensionType.PADDING
    _handshake_types = {HT.CLIENT_HELLO}

    _struct = textwrap.dedent("""
        struct {
            opaque zeros[Extension.extension_length];
        } PaddingExtension;
    """).strip()
    zeros_count: int

    def __init__(self, zeros_count):
        self.zeros_count = zeros_count

    @classmethod
    def parse_body(cls, stream):
        return cls(len(stream.read()))

    def serialize_body(self):
        return b'\x00' * self.zeros_count
