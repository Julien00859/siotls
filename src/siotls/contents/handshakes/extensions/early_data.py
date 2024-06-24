import dataclasses
import textwrap

from siotls.iana import ExtensionType, HandshakeType
from siotls.serial import SerializableBody

from . import Extension


@dataclasses.dataclass(init=False)
class EarlyData(Extension, SerializableBody):
    extension_type = ExtensionType.EARLY_DATA
    _handshake_types = (
        HandshakeType.CLIENT_HELLO,
        HandshakeType.ENCRYPTED_EXTENSIONS
    )

    # The mere presence of the extension is enough
    _struct = ""

    def __init__(self):
        pass

    @classmethod
    def parse_body(cls, stream, **kwargs):  # noqa: ARG003
        return cls()

    def serialize_body(self):
        return b''


@dataclasses.dataclass(init=False)
class NewSessionEarlyData(Extension, SerializableBody):
    extension_type = ExtensionType.EARLY_DATA
    _handshake_types = (HandshakeType.NEW_SESSION_TICKET,)

    _struct = textwrap.dedent("""\
        struct {
            uint32 max_early_data_size;
        } EarlyDataIndication;
    """).strip()
    max_early_data_size: int

    def __init__(self, max_early_data_size):
        self.max_early_data_size = max_early_data_size

    @classmethod
    def parse_body(cls, stream, **kwargs):  # noqa: ARG003
        max_early_data_size = stream.read_int(4)
        return cls(max_early_data_size)

    def serialize_body(self):
        return self.max_early_data_size.to_bytes(4, 'big')
