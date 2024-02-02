import dataclasses

from siotls.iana import HandshakeType
from siotls.serial import SerializableBody

from . import Handshake


@dataclasses.dataclass(init=False)
class CertificateVerify(Handshake, SerializableBody):
    msg_type = HandshakeType.CERTIFICATE_VERIFY
    ...
