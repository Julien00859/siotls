from siotls.iana import HandshakeType
from siotls.serial import SerializableBody
from . import Handshake


class CertificateVerify(Handshake, SerializableBody):
    msg_type = HandshakeType.CERTIFICATE_VERIFY
    ...
