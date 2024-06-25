import dataclasses
import logging
import textwrap
from datetime import datetime, timedelta, timezone

from siotls.contents import alerts
from siotls.contents.handshakes.extensions import Extension
from siotls.iana import ExtensionType, HandshakeType
from siotls.serial import SerializableBody

from . import Handshake

SEVEN_DAYS = 604800

logger = logging.getLogger(__name__)

@dataclasses.dataclass(init=False)
class NewSessionTicket(Handshake, SerializableBody):
    msg_type = HandshakeType.NEW_SESSION_TICKET
    _struct = textwrap.dedent("""
        struct {
            uint32 ticket_lifetime;
            uint32 ticket_age_add;
            opaque ticket_nonce<0..255>;
            opaque ticket<1..2^16-1>;
            Extension extensions<0..2^16-1>;
        } NewSessionTicket;
    """)

    ticket_expires: datetime
    ticket_age_add: int
    ticket_nonce: bytes
    ticket: bytes
    extensions: dict[ExtensionType, Extension]

    def __init__(  # noqa: PLR0913
        self,
        ticket_expires,
        ticket_age_add,
        ticket_nonce,
        ticket,
        extensions: list[Extension]
    ):
        if ticket_expires.tzinfo != timezone.utc:
            e =(f"{ticket_expires=} must be aware and localized in utc")
        if ticket_expires > datetime.now(timezone.utc) + timedelta(days=7):
            e =(f"the ticket would expire on {ticket_expires} which is "
                "over the limit of 7 days by now")
            raise ValueError(e)
        self.ticket_expires = ticket_expires
        self.ticket_age_add = ticket_age_add
        self.ticket_nonce = ticket_nonce
        self.ticket = ticket
        self.extensions = {ext.extension_type: ext for ext in extensions}

    @classmethod
    def parse_body(cls, stream, **kwargs):
        ticket_lifetime = stream.read_int(4)
        if not (0 <= ticket_lifetime <= SEVEN_DAYS):
            e = f"{ticket_lifetime=} must be between 0 and {SEVEN_DAYS=}"
            raise alerts.IllegalParameter(e)
        ticket_expires = datetime.now(timezone.utc) + timedelta(seconds=ticket_lifetime)

        ticket_age_add = stream.read_int(4)
        ticket_nonce = stream.read_var(1)
        ticket = stream.read_var(2)

        extensions = []
        with stream.limit(stream.read_int(2)) as limit:
            while stream.tell() < limit:
                extension = Extension.parse(stream, handshake_type=cls.msg_type, **kwargs)
                extensions.append(extension)

        return cls(ticket_expires, ticket_age_add, ticket_nonce, ticket, extensions)

    def serialize_body(self):
        ticket_lifetime = int((
            self.ticket_expires - datetime.now(timezone.utc)
        ).total_seconds())
        extensions = b''.join(ext.serialize() for ext in self.extensions.values())

        return b''.join([
            ticket_lifetime.to_bytes(4, 'big'),
            self.ticket_age_add.to_bytes(4, 'big'),
            len(self.ticket_nonce).to_bytes(1, 'big'),
            self.ticket_nonce,
            len(self.ticket).to_bytes(2, 'big'),
            self.ticket,
            len(extensions).to_bytes(2, 'big'),
            extensions,
        ])
