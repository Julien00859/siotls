from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody
from . import Extension


class PostHandshakeAuth(Extension, SerializableBody):
    extension_type = ExtensionType.POST_HANDSHAKE_AUTH
    _handshake_types = {HT.CLIENT_HELLO}
