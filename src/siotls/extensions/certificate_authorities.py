import textwrap
from dataclasses import dataclass
from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody
from . import Extension


@dataclass(init=False)
class CertificateAuthorities(Extension, SerializableBody):
    extension_type = ExtensionType.CERTIFICATE_AUTHORITIES
    _handshake_types = {HT.CLIENT_HELLO, HT.CERTIFICATE_REQUEST}

    _struct = textwrap.dedent("""\
        opaque DistinguishedName<1..2^16-1>;

        struct {
            DistinguishedName authorities<3..2^16-1>;
        } CertificateAuthoritiesExtension;
    """).strip()
    autorities: list[bytes]

    def __init__(self, autorities):
        self.autorities = autorities

    @classmethod
    def parse_body(cls, stream):
        autorities = stream.read_listvar(2, 2)
        return cls(autorities)

    def serialize(self):
        autorities = b''.join([
            b''.join([
                len(autority).to_bytes(2, 'big'),
                autority,
            ]) for autority in self.autorities
        ])

        return b''.join([
            len(autorities).to_bytes(2, 'big'),
            autorities,
        ])
