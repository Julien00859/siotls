import dataclasses

from siotls.iana import ExtensionType, HandshakeType
from siotls.serial import SerializableBody

from . import Extension


@dataclasses.dataclass(init=False)
class PostHandshakeAuth(Extension, SerializableBody):
    extension_type = ExtensionType.POST_HANDSHAKE_AUTH
    _handshake_types = (HandshakeType.CLIENT_HELLO,)

    # The mere presence of the extension is enough
    _struct = ""

    def __init__(self):
        pass

    @classmethod
    def parse_body(cls, stream, **kwargs):  # noqa: ARG003  # noqa: ARG003
        return cls()

    def serialize_body(self):
        return b''
