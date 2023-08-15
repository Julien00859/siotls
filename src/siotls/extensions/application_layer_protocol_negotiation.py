from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody
from . import Extension


class ApplicationLayerProtocolNegotiation(Extension, SerializableBody):
    extension_type = ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION
    _handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}
