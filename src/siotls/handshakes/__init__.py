import textwrap
from siotls.iana import ContentType, HandshakeType
from siotls.serial import Serializable
from ..contents import Content, alerts


_handshake_registry = {}

class Handshake(Content, Serializable):
    content_type = ContentType.HANDSHAKE
    can_fragment = True

    _struct = textwrap.dedent("""
        struct {
            HandshakeType msg_type;    /* handshake type */
            uint24 length;             /* remaining bytes in message */
            select (Handshake.msg_type) {
                case 0x01: ClientHello;
                case 0x02: ServerHello;
                case 0x04: EndOfEarlyData;
                case 0x05: EncryptedExtensions;
                case 0x08: CertificateRequest;
                case 0x0b: Certificate;
                case 0x0d: CertificateVerify;
                case 0x0f: Finished;
                case 0x14: NewSessionTicket;
                case 0x18: KeyUpdate;
            };
        } Handshake;
    """).strip('\n')
    msg_type: HandshakeType

    def __init_subclass__(cls, register=True, **kwargs):
        super().__init_subclass__(**kwargs)
        if register and Handshake in cls.__bases__:
            _handshake_registry[cls.msg_type] = cls

    @classmethod
    def parse(abc, stream):
        msg_type = stream.read_int(1)
        length = stream.read_int(3)
        try:
            cls = _handshake_registry[HandshakeType(msg_type)]
        except ValueError as exc:
            raise alerts.UnrecognizedName() from exc

        # ServerHello and HelloRetryRequest share the same handshake id,
        # their "random" field is used to distingate the two
        if msg_type == HandshakeType.SERVER_HELLO:
            with stream.lookahead(), stream.limit(length):
                if stream.read_exactly(34)[2:] == HelloRetryRequest.random:
                    cls = HelloRetryRequest

        with stream.limit(length):
            return cls.parse_body(stream)

    def serialize(self):
        msg_data = self.serialize_body()
        return b''.join([
            self.msg_type.to_bytes(1, 'big'),
            len(msg_data).to_bytes(3, 'big'),
            msg_data,
        ])


# ruff: isort: off
from .client_hello import ClientHello
from .server_hello import ServerHello, HelloRetryRequest
from .end_of_early_data import EndOfEarlyData
from .encrypted_extensions import EncryptedExtensions
from .certificate_request import CertificateRequest
from .certificate import Certificate
from .certificate_verify import CertificateVerify
from .finished import Finished
from .new_session_ticket import NewSessionTicket
from .key_update import KeyUpdate
