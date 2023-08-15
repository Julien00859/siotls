from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody
from . import Extension


class Cookie(Extension, SerializableBody):
    extension_type = ExtensionType.COOKIE
    _handshake_types = {HT.CLIENT_HELLO}
