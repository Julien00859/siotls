import textwrap
from siotls.iana import ExtensionType, HandshakeType as HT, SignatureScheme
from siotls.serial import SerializableBody, SerialIO
from . import Extension


class _SignAlgoMixin(SerializableBody):
    _struct = textwrap.dedent("""
        struct {
            SignatureScheme supported_signature_algorithms<2..2^16-2>;
        } SignatureSchemeList;
    """.strip())
    supported_signature_algorithms: list[SignatureScheme | int]

    def __init__(self, supported_signature_algorithms):
        self.supported_signature_algorithms = supported_signature_algorithms

    @classmethod
    def parse_body(cls, data):
        stream = SerialIO(data)

        supp_sign_algos = []
        it = iter(stream.read_var(2))
        for pair in zip(it, it):
            named_group = (pair[0] << 8) + pair[1]
            try:
                supp_sign_algos.append(SignatureScheme(named_group))
            except ValueError:
                supp_sign_algos.append(named_group)

        stream.assert_eof()
        return cls(supp_sign_algos)

    def serialize_body(self):
        return b''.join([
            (len(self.supported_signature_algorithms) * 2).to_bytes(2, 'big'),
            *[
                sign_algo.to_bytes(2, 'big')
                for sign_algo in self.supported_signature_algorithms
            ]
        ])


class SignatureAlgorithms(Extension, _SignAlgoMixin):
    extension_type = ExtensionType.SIGNATURE_ALGORITHMS
    _handshake_types = {HT.CLIENT_HELLO, HT.CERTIFICATE_REQUEST}


class SignatureAlgorithmsCert(Extension, _SignAlgoMixin):
    extension_type = ExtensionType.SIGNATURE_ALGORITHMS_CERT
    _handshake_types = {HT.CLIENT_HELLO, HT.CERTIFICATE_REQUEST}
