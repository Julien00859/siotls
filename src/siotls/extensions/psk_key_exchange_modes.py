import textwrap
from siotls.iana import ExtensionType, HandshakeType as HT, PskKeyExchangeMode
from siotls.serial import SerializableBody
from siotls.utils import try_cast
from . import Extension


class PskKeyExchangeModes(Extension, SerializableBody):
    extension_type = ExtensionType.PSK_KEY_EXCHANGE_MODES
    _handshake_types = {HT.CLIENT_HELLO}

    _struct = textwrap.dedent("""
        struct {
            PskKeyExchangeMode ke_modes<1..255>;
        } PskKeyExchangeModes;
    """).strip()
    ke_modes: list[PskKeyExchangeMode | int]

    def __init__(self, ke_modes):
        self.ke_modes = ke_modes

    @classmethod
    def parse_body(cls, stream):
        ke_modes = [
            try_cast(PskKeyExchangeMode, ke_mode)
            for ke_mode in stream.read_listint(1, 1)
        ]
        return cls(ke_modes)

    def serialize_body(self):
        return b''.join([
            len(self.ke_modes).to_bytes(1, 'big'),
            *[ke_mode.to_bytes(1, 'big') for ke_mode in self.ke_modes]
        ])
