import dataclasses
import textwrap

from siotls.contents import alerts
from siotls.iana import ContentType, HandshakeType
from siotls.serial import Serializable

from .. import Content  # noqa: TID252

_handshake_registry = {}

@dataclasses.dataclass(init=False)
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
    msg_type: HandshakeType = dataclasses.field(repr=False)

    def __init_subclass__(cls, *, register=True, **kwargs):
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
            raise alerts.UnrecognizedName from exc
        with stream.limit(length):
            return cls.parse_body(stream)

    def serialize(self):
        msg_data = self.serialize_body()
        return b''.join([
            self.msg_type.to_bytes(1, 'big'),
            len(msg_data).to_bytes(3, 'big'),
            msg_data,
        ])


from .certificate import Certificate
from .certificate_request import CertificateRequest
from .certificate_verify import CertificateVerify
from .client_hello import ClientHello
from .encrypted_extensions import EncryptedExtensions
from .end_of_early_data import EndOfEarlyData
from .finished import Finished
from .key_update import KeyUpdate
from .new_session_ticket import NewSessionTicket
from .server_hello import HelloRetryRequest, ServerHello
