import dataclasses
import textwrap
from typing import NamedTuple
from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody, SerialIO
from . import Extension


class OIDFilter(NamedTuple):
    certificate_extension_oid: bytes
    certificate_extension_values: bytes


@dataclasses.dataclass(init=False)
class OIDFilters(Extension, SerializableBody):
    extension_type = ExtensionType.OID_FILTERS
    _handshake_types = {HT.CERTIFICATE_REQUEST}

    _struct = textwrap.dedent("""\
        struct {
            opaque certificate_extension_oid<1..2^8-1>;
            opaque certificate_extension_values<0..2^16-1>;
        } OIDFilter;

        struct {
            OIDFilter filters<0..2^16-1>;
        } OIDFilterExtension;
    """).strip()
    filters: list[OIDFilter]

    def __init__(self, filters):
        self.filters = filters

    @classmethod
    def parse_body(cls, stream):
        filters = []
        list_stream = SerialIO(stream.read_var(2))
        while not list_stream.is_eof():
            cert_ext_oid = list_stream.read_var(1)
            cert_ext_values = list_stream.read_var(2)
            filters.append(OIDFilter(cert_ext_oid, cert_ext_values))
        return cls(filters)

    def serialize_body(self):
        filters = b''.join([
            b''.join([
                len(oidfilter.certificate_extension_oid).to_bytes(1, 'big'),
                oidfilter.certificate_extension_oid,
                len(oidfilter.certificate_extension_values).to_bytes(2, 'big'),
                oidfilter.certificate_extension_values
            ]) for oidfilter in self.filters
        ])

        return b''.join([
            len(filters).to_bytes(2, 'big'),
            filters,
        ])
