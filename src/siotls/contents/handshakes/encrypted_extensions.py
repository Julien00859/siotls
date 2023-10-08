from dataclasses import dataclass
from siotls.iana import HandshakeType
from siotls.serial import SerializableBody
from . import Handshake


@dataclass(init=False)
class EncryptedExtensions(Handshake, SerializableBody):
    msg_type = HandshakeType.ENCRYPTED_EXTENSIONS
    ...
