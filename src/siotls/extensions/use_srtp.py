import itertools
import textwrap
from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody, SerialIO
from . import Extension


class UseSRTP(Extension, SerializableBody):
    extension_type = ExtensionType.USE_SRTP
    _handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}

    _struct = textwrap.dedent("""
        uint8 SRTPProtectionProfile[2];

        struct {
            SRTPProtectionProfiles SRTPProtectionProfiles;
            opaque srtp_mki<0..255>;
        } UseSRTPData;

        SRTPProtectionProfile SRTPProtectionProfiles<2..2^16-1>;
    """.strip())
    protection_profiles: list[int]
    mki: bytes

    def __init__(self, protection_profiles, mki):
        self.protection_profiles = protection_profiles
        self.mki = mki

    @classmethod
    def parse_body(cls, data):
        stream = SerialIO(data)

        it = iter(stream.read_var(2))
        protection_profiles = list(zip(it, it))
        mki = stream.read_var(1)

        stream.assert_eof()
        return cls(protection_profiles, mki)

    def serialize(self):
        return b''.join([
            (len(self.mki) * 2).to_bytes(2, 'big'),
            bytes(itertools.chain.from_iterable(self.protection_profiles)),
            len(self.mki).to_bytes(1, 'big'),
            self.mki,
        ])
