import dataclasses
import textwrap

from siotls.contents import alerts
from siotls.iana import (
    ExtensionType,
    HandshakeType,
    MaxFragmentLengthCode,
    MaxFragmentLengthOctets,
)
from siotls.serial import SerializableBody

from . import Extension


@dataclasses.dataclass(init=False)
class MaxFragmentLength(Extension, SerializableBody):
    extension_type = ExtensionType.MAX_FRAGMENT_LENGTH
    _handshake_types = (
        HandshakeType.CLIENT_HELLO,
        HandshakeType.ENCRYPTED_EXTENSIONS
    )

    _struct = textwrap.dedent("""
        enum {
            2^9(0x01), 2^10(0x02), 2^11(0x03), 2^12(0x04), (0xff)
        } MaxFragmentLength;
    """).strip('\n')
    _max_fragment_length: MaxFragmentLengthCode

    def __init__(
        self,
        code: MaxFragmentLengthCode | None = None,
        octets: MaxFragmentLengthOctets | None = None,
    ):
        if octets and code:
            e = "the code and octets arguments are mutualy exclusive"
            raise ValueError(e)
        elif octets:
            code = MaxFragmentLengthOctets(octets).to_code()
        elif not code:
            e = "missing code or octets arguments"
            raise ValueError(e)
        self._max_fragment_length = code

    @property
    def code(self):
        return self._max_fragment_length

    @property
    def octets(self):
        return self._max_fragment_length.to_octets()

    @classmethod
    def parse_body(cls, stream):
        try:
            max_fragment_length = MaxFragmentLengthCode(stream.read_int(1))
        except ValueError as exc:
            raise alerts.IllegalParameter from exc
        return cls(max_fragment_length)

    def serialize_body(self):
        return self.code.to_bytes(1, 'big')
