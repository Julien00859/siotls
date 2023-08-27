import textwrap
from typing import NamedTuple
from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody, SerialIO
from . import Extension


class PskIdentity(NamedTuple):
    identity: bytes
    obfuscated_ticket_age: int


class PreSharedKeyRequest(Extension, SerializableBody):
    extension_type = ExtensionType.PRE_SHARED_KEY
    _handshake_types = {HT.CLIENT_HELLO}

    def __init__(self, identities, binders):
        self.identities = identities
        self.binders = binders

    _struct = textwrap.dedent("""\
        struct {
            opaque identity<1..2^16-1>;
            uint32 obfuscated_ticket_age;
        } PskIdentity;

        opaque PskBinderEntry<32..255>;

        struct {
            PskIdentity identities<7..2^16-1>;
            PskBinderEntry binders<33..2^16-1>;
        } PreSharedKeyExtension;
    """).strip()
    identities: list[PskIdentity]
    binders: list[bytes]

    @classmethod
    def parse_body(cls, stream):
        identities = []
        list_stream = SerialIO(stream.read_var(2))
        while not list_stream.is_eof():
            identify = list_stream.read_var(2)
            obfuscated_ticket_age = list_stream.read_int(4)
            identities.append(PskIdentity(identify, obfuscated_ticket_age))

        binders = stream.read_listvar(2, 1)

        return cls(identities, binders)

    def serialize_body(self):
        identities = b''.join(
            b''.join([
                len(pskid.identify).to_bytes(2, 'big'),
                pskid.identify,
                pskid.obfuscated_ticket_age.to_bytes(4, 'big')
            ]) for pskid in self.identities
        )

        return b''.join([
            len(identities).to_bytes(2, 'big'),
            identities,
            len(self.binders).to_bytes(2, 'big'),
            *self.binders,
        ])


class PreSharedKeyResponse(Extension, SerializableBody):
    extension_type = ExtensionType.PRE_SHARED_KEY
    _handshake_types = {HT.SERVER_HELLO}

    _struct = textwrap.dedent("""\
        struct {
            uint16 selected_identity;
        } PreSharedKeyExtension;
    """).strip()
    selected_identity: int

    def __init__(self, selected_identity):
        self.selected_identity = selected_identity

    @classmethod
    def parse_body(cls, stream):
        selected_identity = stream.read_int(2)
        return cls(selected_identity)

    def serialize_body(self):
        return self.selected_identity.to_bytes(2, 'big')
