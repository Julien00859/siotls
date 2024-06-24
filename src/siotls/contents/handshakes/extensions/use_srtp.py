import dataclasses
import itertools
import textwrap

from siotls.iana import ExtensionType, HandshakeType
from siotls.serial import SerializableBody

from . import Extension


@dataclasses.dataclass(init=False)
class UseSRTP(Extension, SerializableBody):
    extension_type = ExtensionType.USE_SRTP
    _handshake_types = (
        HandshakeType.CLIENT_HELLO,
        HandshakeType.ENCRYPTED_EXTENSIONS
    )

    _struct = textwrap.dedent("""
        uint8 SRTPProtectionProfile[2];

        struct {
            SRTPProtectionProfiles SRTPProtectionProfiles;
            opaque srtp_mki<0..255>;
        } UseSRTPData;

        SRTPProtectionProfile SRTPProtectionProfiles<2..2^16-1>;
    """).strip()
    protection_profiles: list[int]
    mki: bytes

    def __init__(self, protection_profiles, mki):
        self.protection_profiles = protection_profiles
        self.mki = mki

    @classmethod
    def parse_body(cls, stream, **kwargs):  # noqa: ARG003
        # cannot use read_listint as the type in uint8[2], not uint16
        it = iter(stream.read_var(2))
        protection_profiles = list(zip(it, it, strict=True))
        mki = stream.read_var(1)

        return cls(protection_profiles, mki)

    def serialize(self):
        return b''.join([
            (len(self.mki) * 2).to_bytes(2, 'big'),
            bytes(itertools.chain.from_iterable(self.protection_profiles)),
            len(self.mki).to_bytes(1, 'big'),
            self.mki,
        ])
