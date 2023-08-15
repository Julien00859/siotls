from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody
from . import Extension


class Padding(Extension, SerializableBody):
    extension_type = ExtensionType.PADDING
    _handshake_types = {HT.CLIENT_HELLO}
