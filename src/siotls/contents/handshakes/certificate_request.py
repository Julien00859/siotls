from siotls.iana import HandshakeType
from siotls.serial import SerializableBody
from . import Handshake


class CertificateRequest(Handshake, SerializableBody):
    msg_type = HandshakeType.CERTIFICATE_REQUEST
    ...
