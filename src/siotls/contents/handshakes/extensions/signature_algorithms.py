import dataclasses
import textwrap
from siotls.iana import ExtensionType, HandshakeType as HT, SignatureScheme
from siotls.serial import SerializableBody
from siotls.utils import try_cast
from . import Extension


class _SignAlgoMixin(SerializableBody):
    _struct = textwrap.dedent("""
        struct {
            SignatureScheme supported_signature_algorithms<2..2^16-2>;
        } SignatureSchemeList;
    """).strip()

    def __init__(self, supported_signature_algorithms):
        self.supported_signature_algorithms = supported_signature_algorithms

    @classmethod
    def parse_body(cls, stream):
        supported_signature_algorithms = [
            try_cast(SignatureScheme, signature_scheme)
            for signature_scheme in stream.read_listint(2, 2)
        ]
        return cls(supported_signature_algorithms)

    def serialize_body(self):
        return b''.join([
            (len(self.supported_signature_algorithms) * 2).to_bytes(2, 'big'),
            *[
                sign_algo.to_bytes(2, 'big')
                for sign_algo in self.supported_signature_algorithms
            ]
        ])


@dataclasses.dataclass(init=False)
class SignatureAlgorithms(Extension, _SignAlgoMixin):
    extension_type = ExtensionType.SIGNATURE_ALGORITHMS
    _handshake_types = {HT.CLIENT_HELLO, HT.CERTIFICATE_REQUEST}
    supported_signature_algorithms: list[SignatureScheme | int]


@dataclasses.dataclass(init=False)
class SignatureAlgorithmsCert(Extension, _SignAlgoMixin):
    extension_type = ExtensionType.SIGNATURE_ALGORITHMS_CERT
    _handshake_types = {HT.CLIENT_HELLO, HT.CERTIFICATE_REQUEST}
    supported_signature_algorithms: list[SignatureScheme | int]
