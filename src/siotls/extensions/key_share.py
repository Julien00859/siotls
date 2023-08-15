from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody
from . import Extension


class KeyShare(Extension, SerializableBody):
    extension_type = ExtensionType.KEY_SHARE
    _handshake_types = {HT.CLIENT_HELLO, HT.SERVER_HELLO}
