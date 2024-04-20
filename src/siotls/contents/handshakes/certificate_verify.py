import dataclasses
import textwrap

from siotls.iana import HandshakeType, SignatureScheme
from siotls.serial import SerializableBody
from siotls.utils import try_cast

from . import Handshake


@dataclasses.dataclass(init=False)
class CertificateVerify(Handshake, SerializableBody):
    msg_type = HandshakeType.CERTIFICATE_VERIFY

    _struct = textwrap.dedent("""
        struct {
            SignatureScheme algorithm;
            opaque signature<0..2^16-1>;
        } CertificateVerify;
    """)
    algorithm: SignatureScheme | int
    signature: bytes

    def __init__(self, algorithm, signature):
        self.algorithm = algorithm
        self.signature = signature

    @classmethod
    def parse_body(cls, stream):
        algorithm = try_cast(SignatureScheme, stream.read_int(2))
        signature = stream.read_var(2)
        return cls(algorithm, signature)

    def serialize_body(self):
        return b''.join([
            self.algorithm.to_bytes(2, 'big'),
            len(self.signature).to_bytes(2, 'big'),
            self.signature,
        ])
