from siotls.iana import ExtensionType, HandshakeType as HT, CertificateType
from siotls.serial import SerializableBody, SerialIO
from siotls.utils import try_cast
from . import Extension


class _CertificateTypeRequest(SerializableBody):
    _handshake_types = {HT.CLIENT_HELLO}

    def __init__(self, certificate_types):
        self.certificate_types = certificate_types

    @classmethod
    def parse_body(cls, data):
        stream = SerialIO(data)
        self = cls([
            try_cast(CertificateType, word)
            for word in stream.read_var(1)
        ])
        stream.assert_eof()
        return self

    def serialize_body(self):
        return b''.join([
            len(self.certificate_type).to_bytes(1, 'big'),
            *[ct.to_bytes(1, 'big') for ct in self.certificate_types],
        ])

class _CertificateTypeResponse(SerializableBody):
    _handshake_types = {HT.ENCRYPTED_EXTENSIONS}

    def __init__(self, certificate_type):
        self.certificate_type = certificate_type

    @classmethod
    def parse_body(cls, data):
        stream = SerialIO(data)
        self = cls(stream.read_int(1))
        stream.assert_eof()
        return self

    @classmethod
    def serialize_body(self):
        return self.certificate_type.to_bytes(1, 'big')

class ClientCertificateTypeRequest(Extension, _CertificateTypeRequest):
    extension_type = ExtensionType.CLIENT_CERTIFICATE_TYPE

class ClientCertificateTypeResponse(Extension, _CertificateTypeResponse):
    extension_type = ExtensionType.CLIENT_CERTIFICATE_TYPE

class ServerCertificateTypeRequest(Extension, _CertificateTypeRequest):
    extension_type = ExtensionType.SERVER_CERTIFICATE_TYPE

class ServerCertificateTypeResponse(Extension, _CertificateTypeResponse):
    extension_type = ExtensionType.SERVER_CERTIFICATE_TYPE
