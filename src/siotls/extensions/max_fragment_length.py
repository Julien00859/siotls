import textwrap
from dataclasses import dataclass
from siotls.iana import ExtensionType, HandshakeType as HT, MaxFragmentLength
from siotls.serial import SerializableBody, SerializationError
from . import Extension
from ..contents import alerts

to_int = {
    MaxFragmentLength.MAX_512: 512,
    MaxFragmentLength.MAX_1024: 1024,
    MaxFragmentLength.MAX_2048: 2048,
    MaxFragmentLength.MAX_4096: 4096,
}.__getitem__
to_enum = {
    512: MaxFragmentLength.MAX_512,
    1024: MaxFragmentLength.MAX_1024,
    2048: MaxFragmentLength.MAX_2048,
    4096: MaxFragmentLength.MAX_4096,
}.__getitem__


@dataclass(init=False)
class MaxFragmentLength(Extension, SerializableBody):
    extension_type = ExtensionType.MAX_FRAGMENT_LENGTH
    _handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}

    _struct = textwrap.dedent("""
        enum {
            2^9(0x01), 2^10(0x02), 2^11(0x03), 2^12(0x04), (0xff)
        } MaxFragmentLength;
    """).strip('\n')
    max_fragment_length: int

    def __init__(self, max_fragment_length: MaxFragmentLength):
        self.max_fragment_length = to_int(max_fragment_length)

    @classmethod
    def parse_body(cls, stream):
        try:
            max_fragment_length = MaxFragmentLength(stream.read_int(1))
        except SerializationError:
            raise
        except ValueError as exc:
            raise alerts.IllegalParameter() from exc
        return cls(max_fragment_length)

    def serialize_body(self):
        return to_enum(self.max_fragment_length).to_bytes(1, 'big')
