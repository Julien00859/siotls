from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody
from . import Extension


class OidFilters(Extension, SerializableBody):
    extension_type = ExtensionType.OID_FILTERS
    _handshake_types = {HT.CERTIFICATE_REQUEST}
