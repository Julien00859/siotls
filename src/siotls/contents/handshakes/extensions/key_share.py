import dataclasses
import textwrap

from siotls.contents import alerts
from siotls.iana import (
    ExtensionType,
    HandshakeType,
    HandshakeType_,
    NamedGroup,
)
from siotls.serial import SerialIO, SerializableBody, SerializationError
from siotls.utils import try_cast

from . import Extension


@dataclasses.dataclass(init=False)
class KeyShareRequest(Extension, SerializableBody):
    extension_type = ExtensionType.KEY_SHARE
    _handshake_types = (HandshakeType.CLIENT_HELLO,)

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
            key_exchange = try_cast(NamedGroup, list_stream.read_int(2))
            key_share = list_stream.read_var(2)
            if key_exchange in client_shares:
                e = "Cannot share different keys for a same group"
                raise alerts.IllegalParameter(e)
            client_shares[key_exchange] = key_share
        return cls(client_shares)

    def serialize_body(self):
        client_shares = b''.join([
            b''.join([
                key_exchange.to_bytes(2, 'big'),
                len(key_share).to_bytes(2, 'big'),
                key_share,
            ]) for key_exchange, key_share in self.client_shares.items()
        ])

        return b''.join([
            len(client_shares).to_bytes(2, 'big'),
            client_shares,
        ])


@dataclasses.dataclass(init=False)
class KeyShareRetry(Extension, SerializableBody):
    extension_type = ExtensionType.KEY_SHARE
    _handshake_types = (HandshakeType_.HELLO_RETRY_REQUEST,)

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
            raise alerts.IllegalParameter from exc
        return cls(selected_group)

    def serialize_body(self):
        return self.selected_group.to_bytes(2, 'big')


@dataclasses.dataclass(init=False)
class KeyShareResponse(Extension, SerializableBody):
    extension_type = ExtensionType.KEY_SHARE
    _handshake_types = (HandshakeType.SERVER_HELLO,)

    _struct = textwrap.dedent("""\
        struct {
            NamedGroup group;
            opaque key_exchange<1..2^16-1>;
        } KeyShareEntry;

        struct {
            KeyShareEntry server_share;
        } KeyShareServerHello;
    """).strip()
    group: NamedGroup | int
    key_exchange: bytes

    def __init__(self, group, key_exchange):
        self.group = group
        self.key_exchange = key_exchange

    @classmethod
    def parse_body(cls, stream):
        group = try_cast(NamedGroup, stream.read_int(2))
        key_exchange = stream.read_var(2)
        return cls(group, key_exchange)

    def serialize_body(self):
        return b''.join([
            self.group.to_bytes(2, 'big'),
            len(self.key_exchange).to_bytes(2, 'big'),
            self.key_exchange,
        ])
