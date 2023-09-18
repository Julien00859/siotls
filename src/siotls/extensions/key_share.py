import textwrap
from siotls.contents import alerts
from siotls.iana import ExtensionType, HandshakeType as HT, NamedGroup
from siotls.serial import SerializableBody, SerialIO, SerializationError
from siotls.utils import try_cast
from . import Extension

sizes = {
    NamedGroup.secp256r1: 32,
    NamedGroup.secp384r1: 48,
    NamedGroup.secp521r1: 66,
    NamedGroup.x25519: 32,
    NamedGroup.x448: 56,
}


class KeyShareRequest(Extension, SerializableBody):
    extension_type = ExtensionType.KEY_SHARE
    _handshake_types = {HT.CLIENT_HELLO}

    _struct = textwrap.dedent("""\
        struct {
            NamedGroup group;
            opaque key_exchange<1..2^16-1>;
        } KeyShareEntry;

        struct {
            KeyShareEntry client_shares<0..2^16-1>;
        } KeyShareClientHello;
    """).strip()
    client_shares: dict[NamedGroup | int, bytes]

    def __init__(self, client_shares):
        self.client_shares = client_shares

    @classmethod
    def parse_body(cls, stream):
        client_shares = {}
        list_stream = SerialIO(stream.read_var(2))
        while not list_stream.is_eof():
            group = try_cast(NamedGroup, list_stream.read_int(2))
            key_exchange = list_stream.read_var(2)
            if group in client_shares:
                raise alerts.IllegalParameter()
            client_shares[group] = key_exchange
        return cls(client_shares)

    def serialize_body(self):
        client_shares = b''.join([
            b''.join([
                entry.group.to_bytes(2, 'big'),
                len(entry.key_exchange).to_bytes(2, 'big'),
                entry.key_exchange,
            ]) for entry in self.client_shares
        ])

        return b''.join([
            len(client_shares).to_bytes(2, 'big'),
            client_shares,
        ])


class KeyShareRetry(Extension, SerializableBody):
    extension_type = ExtensionType.KEY_SHARE
    _handshake_types = {HT.SERVER_HELLO}

    _struct = textwrap.dedent("""\
        struct {
            NamedGroup selected_group;
        } KeyShareHelloRetryRequest;
    """).strip()
    selected_group: NamedGroup

    def __init__(self, selected_group):
        self.selected_group = selected_group

    @classmethod
    def parse_body(cls, stream):
        try:
            selected_group = NamedGroup(stream.read_int(2))
        except SerializationError:
            raise
        except ValueError as exc:
            raise alerts.IllegalParameter() from exc
        return cls(selected_group)

    def serialize_body(self):
        return self.selected_group.to_bytes(2, 'big')


class KeyShareResponse(Extension, SerializableBody):
    extension_type = ExtensionType.KEY_SHARE
    _handshake_types = {HT.SERVER_HELLO}

    _struct = textwrap.dedent("""\
        struct {
            KeyShareEntry server_share;
        } KeyShareServerHello;
    """).strip()
    server_share_group: NamedGroup | int
    server_share_key_exchange: bytes

    @classmethod
    def parse_body(cls, stream):
        group = try_cast(NamedGroup, stream.read_int(2))
        key_exchange = stream.read_var(2)
        return cls(group, key_exchange)

    def serialize_body(self):
        return b''.join(
            self.group.to_bytes(2, 'big'),
            len(self.server_share_key_exchange).to_bytes(2, 'big'),
            self.server_share_key_exchange,
        )
