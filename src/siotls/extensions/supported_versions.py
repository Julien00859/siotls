import textwrap
from siotls.iana import ExtensionType, HandshakeType as HT, TLSVersion
from siotls.serial import SerializableBody, SerialIO
from siotls.utils import try_cast
from . import Extension


class SupportedVersionsRequest(Extension, SerializableBody):
    extension_type = ExtensionType.SUPPORTED_VERSIONS
    _handshake_types = {HT.CLIENT_HELLO}

    _struct = textwrap.dedent("""\
        struct {
            ProtocolVersion versions<2..254>;
        } SupportedVersions;
    """).strip()
    versions: list[TLSVersion | int]

    def __init__(self, versions):
        self.versions = versions

    @classmethod
    def parse_body(cls, data):
        stream = SerialIO(data)
        versions = [
            try_cast(TLSVersion, i)
            for i in stream.read_varint(1, sizeof=2)
        ]
        stream.assert_eof()
        return cls(versions)

    def serialize_body(self):
        return b''.join([
            (len(self.versions) * 2).to_bytes(1, 'big'),
            *[version.to_bytes(2, 'big') for version in self.versions]
        ])


class SupportedVersionsResponse(Extension, SerializableBody):
    extension_type = ExtensionType.SUPPORTED_VERSIONS
    _handshake_types = {HT.SERVER_HELLO}

    _struct = textwrap.dedent("""\
        struct {
            ProtocolVersion selected_version;
        } SupportedVersions;
    """).strip()
    selected_version: TLSVersion

    def __init__(self, selected_version):
        if selected_version < TLSVersion.TLS_1_3:
            msg = ("Versions prior to TLS 1.3 must set the version on "
                   "the record (legacy_version) instead.")
            raise ValueError(msg)
        self.selected_version = selected_version

    @classmethod
    def parse_body(cls, data):
        stream = SerialIO(data)
        selected_version = stream.read_int(2, 'big')
        stream.assert_eof()
        return cls(selected_version)

    def serialize_body(self):
        return self.selected_version.to_bytes(2, 'big')
