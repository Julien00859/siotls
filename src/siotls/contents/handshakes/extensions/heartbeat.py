import dataclasses
import textwrap

from siotls.contents import alerts
from siotls.iana import ExtensionType, HandshakeType, HeartbeatMode
from siotls.serial import SerializableBody

from . import Extension


@dataclasses.dataclass(init=False)
class Heartbeat(Extension, SerializableBody):
    extension_type = ExtensionType.HEARTBEAT
    _handshake_types = (
        HandshakeType.CLIENT_HELLO,
        HandshakeType.ENCRYPTED_EXTENSIONS
    )

    _struct = textwrap.dedent("""
        struct {
            HeartbeatMode mode;
        } HeartbeatExtension;
    """).strip()
    mode: HeartbeatMode

    def __init__(self, mode):
        self.mode = mode

    @classmethod
    def parse_body(cls, stream, **kwargs):  # noqa: ARG003
        try:
            mode = HeartbeatMode(stream.read_int(1))
        except ValueError as exc:
            raise alerts.IllegalParameter(*exc.args) from exc
        return cls(mode)

    def serialize_body(self):
        return self.mode.to_bytes(1, 'big')
