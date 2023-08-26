from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody, TooMuchData
from . import Extension


class PostHandshakeAuth(Extension, SerializableBody):
    extension_type = ExtensionType.POST_HANDSHAKE_AUTH
    _handshake_types = {HT.CLIENT_HELLO}

    _struct = ''

    def __init__(self):
        pass

    @classmethod
    def parse_body(cls, data):
        if data:
            msg = f"Expected end of stream but {len(data)} bytes remain."
            raise TooMuchData(msg)
        return cls()

    def serialize_body(self):
        return b''
