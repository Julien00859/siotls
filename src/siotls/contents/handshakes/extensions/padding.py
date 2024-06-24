import dataclasses
import textwrap

from siotls.iana import ExtensionType, HandshakeType
from siotls.serial import SerializableBody

from . import Extension


@dataclasses.dataclass(init=False)
class Padding(Extension, SerializableBody):
    extension_type = ExtensionType.PADDING
    _handshake_types = (HandshakeType.CLIENT_HELLO,)

    _struct = textwrap.dedent("""
        struct {
            opaque zeros[Extension.extension_length];
        } PaddingExtension;
    """).strip()
    zeros_count: int

    def __init__(self, zeros_count):
        self.zeros_count = zeros_count

    @classmethod
    def parse_body(cls, stream, **kwargs):  # noqa: ARG003
        return cls(len(stream.read()))

    def serialize_body(self):
        return b'\x00' * self.zeros_count
