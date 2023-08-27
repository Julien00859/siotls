import textwrap
from siotls.iana import ExtensionType, HandshakeType as HT, HeartbeatMode
from siotls.serial import SerializableBody, SerializationError
from . import Extension
from ..contents import alerts


class Heartbeat(Extension, SerializableBody):
    extension_type = ExtensionType.HEARTBEAT
    _handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}

    _struct = textwrap.dedent("""
        struct {
            HeartbeatMode mode;
        } HeartbeatExtension;
    """).strip()
    mode: HeartbeatMode

    def __init__(self, mode):
        self.mode = mode

    @classmethod
    def parse_body(cls, stream):
        try:
            mode = HeartbeatMode(stream.read_int(1))
        except SerializationError:
            raise
        except ValueError as exc:
            raise alerts.IllegalParameter() from exc
        return cls(mode)

    def serialize_body(self):
        return self.mode.to_bytes(1, 'big')
