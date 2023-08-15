import textwrap
from siotls.iana import ExtensionType, HandshakeType as HT, MaxFragmentLength
from siotls.serial import SerializableBody
from . import Extension
from ..contents import alerts


class MaxFragmentLength(Extension, SerializableBody):
    extension_type = ExtensionType.MAX_FRAGMENT_LENGTH
    _handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}

    _struct = textwrap.dedent("""
        enum {
            2^9(0x01), 2^10(0x02), 2^11(0x03), 2^12(0x04), (0xff)
        } MaxFragmentLength;
    """).strip('\n')
    max_fragment_length: MaxFragmentLength

    def __init__(self, max_fragment_length):
        self.max_fragment_length = max_fragment_length

    @classmethod
    def parse_body(cls, data):
        if len(data) != 1:
            raise ValueError(f"Expected exactly 1 byte but found {len(data)}")
        max_fragment_length = int.from_bytes(data[0], 'big')
        try:
            max_fragment_length = MaxFragmentLength(max_fragment_length)
        except ValueError as exc:
            raise alerts.IllegalParameter() from exc
        return cls(max_fragment_length)

    def serialize_body(self):
        return self.max_fragment_length.to_bytes(1, 'big')
