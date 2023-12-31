import dataclasses
import textwrap
from siotls.iana import (
    ExtensionType,
    HandshakeType as HT,
    HandshakeType_ as HT_,
    TLSVersion,
)
from siotls.serial import SerializableBody, SerializationError
from siotls.utils import try_cast
from ... import alerts
from . import Extension


@dataclasses.dataclass(init=False)
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
    def parse_body(cls, stream):
        versions = [
            try_cast(TLSVersion, version)
            for version in stream.read_listint(1, 2)
        ]
        return cls(versions)

    def serialize_body(self):
        return b''.join([
            (len(self.versions) * 2).to_bytes(1, 'big'),
            *[version.to_bytes(2, 'big') for version in self.versions]
        ])


@dataclasses.dataclass(init=False)
class SupportedVersionsResponse(Extension, SerializableBody):
    extension_type = ExtensionType.SUPPORTED_VERSIONS
    _handshake_types = [HT.SERVER_HELLO, HT_.HELLO_RETRY_REQUEST]

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
    def parse_body(cls, stream):
        try:
            selected_version = TLSVersion(stream.read_int(2))
        except SerializationError:
            raise
        except ValueError as exc:
            raise alerts.IllegalParameter() from exc
        return cls(selected_version)

    def serialize_body(self):
        return self.selected_version.to_bytes(2, 'big')
