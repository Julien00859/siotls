import textwrap
from typing import NamedTuple
from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody, SerialIO
from . import Extension


class OIDFilter(NamedTuple):
    certificate_extension_oid: bytes
    certificate_extension_values: bytes


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
    def parse_body(cls, data):
        stream = SerialIO(data)

        filters = []
        list_length = stream.read_int(2)
        while list_length > 0:
            cert_ext_oid = stream.read_var(1)
            list_length -= len(cert_ext_oid) - 1
            cert_ext_values = stream.read_var(2)
            list_length -= len(cert_ext_values) - 2
            filters.append(OIDFilter(cert_ext_oid, cert_ext_values))
        if list_length < 0:
            raise RuntimeError(f"buffer overflow while parsing {data}")

        stream.assert_eof()
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
