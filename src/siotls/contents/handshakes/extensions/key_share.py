import dataclasses
import textwrap
from typing import NamedTuple
from siotls.iana import ExtensionType, HandshakeType as HT, NamedGroup
from siotls.serial import SerializableBody, SerialIO, SerializationError
from siotls.utils import try_cast
from ... import alerts
from . import Extension


class KeyShareEntry(NamedTuple):
    group: NamedGroup | int
    key_exchange: bytes


@dataclasses.dataclass(init=False)
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
    client_shares: list[KeyShareEntry]

    def __init__(self, client_shares):
        self.client_shares = client_shares

    @classmethod
    def parse_body(cls, stream):
        client_shares = []
        list_stream = SerialIO(stream.read_var(2))
        while not list_stream.is_eof():
            group = try_cast(NamedGroup, list_stream.read_int(2))
            key_exchange = list_stream.read_var(2)
            client_shares.append(KeyShareEntry(group, key_exchange))
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

@dataclasses.dataclass(init=False)
class KeyShareResponse(Extension, SerializableBody):
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
