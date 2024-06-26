import dataclasses
import logging
import textwrap

from siotls.contents import alerts
from siotls.iana import CipherSuites, ExtensionType, HandshakeType, HandshakeType_, TLSVersion
from siotls.serial import SerialIO, SerializableBody
from siotls.utils import try_cast

from . import Handshake
from .extensions import Extension

logger = logging.getLogger(__name__)


@dataclasses.dataclass(init=False)
class ServerHello(Handshake, SerializableBody):
    msg_type = HandshakeType.SERVER_HELLO

    _struct = textwrap.dedent("""
        uint16 ProtocolVersion;
        opaque Random[32];

        uint8 CipherSuite[2];    /* Cryptographic suite selector */

        struct {
            ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
            Random random;
            opaque legacy_session_id_echo<0..32>;
            CipherSuite cipher_suite;
            uint8 legacy_compression_method = 0;
            Extension extensions<6..2^16-1>;
        } ServerHello;
    """).strip('\n')
    legacy_version: int = dataclasses.field(default=TLSVersion.TLS_1_2, repr=False)
    random: bytes
    legacy_session_id_echo: bytes = dataclasses.field(repr=False)
    cipher_suite: CipherSuites | int
    legacy_compression_methods: int = dataclasses.field(default=0, repr=False)
    extensions: dict[ExtensionType | int, Extension]

    def __init__(
        self,
        random,
        legacy_session_id_echo,
        cipher_suite,
        extensions: list[Extension]
    ):
        self.legacy_version = type(self).legacy_version
        self.random = random
        self.legacy_session_id_echo = legacy_session_id_echo
        self.cipher_suite = cipher_suite
        self.legacy_compression_methods = type(self).legacy_compression_methods
        self.extensions = {ext.extension_type: ext for ext in extensions}

    @classmethod
    def parse_body(cls, stream, **kwargs):
        legacy_version = stream.read_int(2)
        if legacy_version != TLSVersion.TLS_1_2:
            e = f"expected {TLSVersion.TLS_1_2} but {legacy_version} found"
            raise alerts.ProtocolVersion(e)
        legacy_version = TLSVersion(legacy_version)

        random = stream.read_exactly(32)
        if random == HelloRetryRequest.random:
            cls = HelloRetryRequest

        legacy_session_id_echo = stream.read_var(1)

        cipher_suite = try_cast(CipherSuites, stream.read_int(2))

        legacy_compression_methods = stream.read_int(1)
        if legacy_compression_methods != 0:  # "null" compression method
            e = "only the NULL compression method is supported in TLS 1.3"
            raise alerts.IllegalParameter(e)

        extensions = []
        list_stream = SerialIO(stream.read_var(2))
        while not list_stream.is_eof():
            extension = Extension.parse(list_stream, handshake_type=cls.msg_type, **kwargs)
            extensions.append(extension)

        return cls(random, legacy_session_id_echo, cipher_suite, extensions)

    def serialize_body(self):
        extensions = b''.join(ext.serialize() for ext in self.extensions.values())

        return b''.join([
            self.legacy_version.to_bytes(2, 'big'),
            self.random,
            len(self.legacy_session_id_echo).to_bytes(1, 'big'),
            self.legacy_session_id_echo,
            self.cipher_suite.to_bytes(2, 'big'),
            self.legacy_compression_methods.to_bytes(1, 'big'),
            len(extensions).to_bytes(2, 'big'),
            extensions,
        ])


class HelloRetryRequest(ServerHello):
    msg_type = HandshakeType_.HELLO_RETRY_REQUEST

    # hashlib.sha256("HelloRetryRequest").digest()
    random = bytes.fromhex(
        "CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91"
        "C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C"
    )
