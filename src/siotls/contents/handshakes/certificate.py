import dataclasses
import textwrap

from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)
from cryptography.x509 import Certificate, load_der_x509_certificate

from siotls.contents import alerts
from siotls.iana import CertificateType, ExtensionType, HandshakeType
from siotls.serial import SerialIO, Serializable, SerializableBody

from . import Handshake
from .extensions import Extension

_certificate_entry_registry = {}


@dataclasses.dataclass(init=False)
class CertificateEntry(Serializable):
    _struct = textwrap.dedent("""
        enum {
            X509(0),
            RawPublicKey(2),
            (255)
        } CertificateType;

        struct {
            select (certificate_type) {
                case RawPublicKey:
                    /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
                    opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;

                case X509:
                    opaque cert_data<1..2^24-1>;
            };
            Extension extensions<0..2^16-1>;
        } CertificateEntry;
    """)

    def __init_subclass__(cls, *, register=True, **kwargs):
        super().__init_subclass__(**kwargs)
        if register and CertificateEntry in cls.__bases__:
            _certificate_entry_registry[cls.certificate_type] = cls

    @classmethod
    def parse(cls, stream):
        data = stream.read_var(3)
        certificate = cls._parse_certificate(data)

        extensions = []
        list_stream = SerialIO(stream.read_var(2))
        while not list_stream.is_eof():
            extension = Extension.parse(list_stream, handshake_type=HandshakeType.CERTIFICATE)
            extensions.append(extension)

        return cls(certificate, extensions)

    def serialize(self):
        extensions = b''.join(ext.serialize() for ext in self.extensions.values())
        certificate = self._serialize_certificate()

        return b''.join([
            len(certificate).to_bytes(3, 'big'),
            certificate,
            len(extensions).to_bytes(2, 'big'),
            extensions,
        ])


class X509(CertificateEntry):
    certificate_type = CertificateType.X509
    certificate: Certificate
    extensions: dict[ExtensionType | int, Extension]

    def __init__(self, certificate, extensions):
        self.certificate = certificate
        self.extensions = {ext.extension_type: ext for ext in extensions}

    @classmethod
    def _parse_certificate(cls, data):
        return load_der_x509_certificate(data)

    def _serialize_certificate(self):
        return self.certificate.public_bytes(Encoding.DER)


class RawPublicKey(CertificateEntry):
    certificate_type = CertificateType.RAW_PUBLIC_KEY
    public_key: PublicKeyTypes
    extensions: dict[ExtensionType | int, Extension]

    def __init__(self, public_key, extensions):
        self.public_key = public_key
        self.extensions = {ext.extension_type: ext for ext in extensions}

    @classmethod
    def _parse_certificate(cls, data):
        return load_der_public_key(data)

    def _serialize_certificate(self):
        return self.public_key.public_bytes(
            Encoding.DER,
            PublicFormat.SubjectPublicKeyInfo,
        )


@dataclasses.dataclass(init=False)
class Certificate(Handshake, SerializableBody):
    msg_type = HandshakeType.CERTIFICATE
    _struct = textwrap.dedent("""
        struct {
            opaque certificate_request_context<0..2^8-1>;
            CertificateEntry certificate_list<0..2^24-1>;
        } Certificate;
    """).strip('\n')

    certificate_request_context: bytes
    certificate_list: list[CertificateEntry]

    def __init__(self, certificate_request_context, certificate_list):
        self.certificate_request_context = certificate_request_context
        self.certificate_list = certificate_list

    @classmethod
    def parse_body(cls, stream, *, certificate_type):
        try:
            Entry = _certificate_entry_registry[certificate_type]  # noqa: N806
        except IndexError as exc:
            raise alerts.CertificateUnknown(*exc.args) from exc

        certificate_request_context = stream.read_var(1)

        certificate_list = []
        with stream.limit(stream.read_int(3)) as limit:
            while stream.tell() < limit:
                certificate = Entry.parse(stream)
                certificate_list.append(certificate)

        try:
            return cls(certificate_request_context, certificate_list)
        except ValueError as exc:
            raise alerts.IllegalParameter(*exc.args) from exc

    def serialize_body(self):
        certificates = b''.join(cert.serialize() for cert in self.certificate_list)

        return b''.join([
            len(self.certificate_request_context).to_bytes(1, 'big'),
            self.certificate_request_context,
            len(certificates).to_bytes(3, 'big'),
            certificates
        ])
