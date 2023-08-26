import textwrap
from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody, SerialIO
from . import Extension


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
    def parse_body(cls, data):
        stream = SerialIO(data)

        autorities = []
        list_length = stream.read_int(2)
        while list_length > 0:
            autority = stream.read_var(2, limit=list_length)
            list_length -= len(autority) + 2
            autorities.append(autority)
        if list_length < 0:
            raise RuntimeError(f"buffer overflow while parsing {data}")

        stream.assert_eof()
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
