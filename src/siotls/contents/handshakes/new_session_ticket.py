from siotls.iana import HandshakeType
from siotls.serial import SerializableBody
from . import Handshake


class NewSessionTicket(Handshake, SerializableBody):
    msg_type = HandshakeType.NEW_SESSION_TICKET
    ...
