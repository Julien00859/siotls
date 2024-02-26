import dataclasses
import textwrap

from siotls.iana import ContentType, HeartbeatMessageType
from siotls.serial import Serializable

from . import Content, alerts


@dataclasses.dataclass(init=False)
class Heartbeat(Content, Serializable):
    content_type = ContentType.HEARTBEAT
    can_fragment = False

    _struct = textwrap.dedent("""
        struct {
            HeartbeatMessageType type;
            uint16 payload_length;
            opaque payload[HeartbeatMessage.payload_length];
            opaque padding[padding_length];
        } HeartbeatMessage;
    """).strip('\n')
    heartbeat_type: HeartbeatMessageType
    payload: bytes
    padding: bytes

    def __init__(self, heartbeat_type, payload, padding):
        # TODO: MaxFragmentLength
        if len(payload) > 2 ** 14 - 3:
            e = f"payload too long: {len(payload)} > {2 ** 14 - 3}"
            raise ValueError(e)
        if len(padding) > 2 ** 14 - 3 - len(payload):
            e = f"padding too long: {len(padding)} > {2 ** 14 - 3 - len(payload)}"
            raise ValueError(e)
        self.heartbeat_type = heartbeat_type
        self.payload = payload
        self.padding = padding

    @classmethod
    def parse(cls, stream):
        try:
            heartbeat_type = HeartbeatMessageType(stream.read_int(1))
        except ValueError as exc:
            raise alerts.IllegalParameter(*exc.args) from exc
        payload = stream.read_var(2)
        padding = stream.read()
        return cls(heartbeat_type, payload, padding)

    def serialize(self):
        return b''.join(
            self.heartbeat_type.to_bytes(1, 'big'),
            len(self.payload).to_bytes(2, 'big'),
            self.payload,
            self.padding,
        )
