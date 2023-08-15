from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody
from . import Extension


class SupportedVersions(Extension, SerializableBody):
    extension_type = ExtensionType.SUPPORTED_VERSIONS
    _handshake_types = {HT.CLIENT_HELLO, HT.SERVER_HELLO}
