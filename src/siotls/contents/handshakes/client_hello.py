import dataclasses
import logging
import textwrap

from siotls.contents import alerts
from siotls.iana import CipherSuites, ExtensionType, HandshakeType, TLSVersion
from siotls.serial import SerialIO, SerializableBody
from siotls.utils import try_cast

from . import Handshake
from .extensions import Extension

logger = logging.getLogger(__name__)


def _find_duplicated_extension(extensions):
    for ext_no, ext1 in enumerate(extensions):
        for ext2 in extensions[ext_no+1:]:
            if ext1.extension_type != ext2.extension_type:
                continue
            if ext1 != ext2:
                e = f"duplicated extension: {ext1} vs {ext2}"
                raise ValueError(e)
            else:
                logger.warning("duplicated extension: %s", ext1)


@dataclasses.dataclass(init=False)
class ClientHello(Handshake, SerializableBody):
    msg_type = HandshakeType.CLIENT_HELLO
    _struct = textwrap.dedent("""
        uint16 ProtocolVersion;
        opaque Random[32];

        uint8 CipherSuite[2];    /* Cryptographic suite selector */

        struct {
            ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
            Random random;
            opaque legacy_session_id<0..32>;
            CipherSuite cipher_suites<2..2^16-2>;
            opaque legacy_compression_methods<1..2^8-1>;
            Extension extensions<8..2^16-1>;
        } ClientHello;
    """).strip('\n')

    legacy_version: int = dataclasses.field(default=TLSVersion.TLS_1_2, repr=False)
    random: bytes
    legacy_session_id: bytes = dataclasses.field(default=b'', repr=False)
    cipher_suites: list[CipherSuites | int]
    legacy_compression_methods: bytes = dataclasses.field(default=b'\x00', repr=False)
    extensions: dict[ExtensionType | int, Extension]

    def __init__(self, random, cipher_suites, extensions: list[Extension]):
        self.legacy_version = type(self).legacy_version
        self.random = random
        self.legacy_session_id = type(self).legacy_session_id
        self.cipher_suites = cipher_suites
        self.legacy_compression_methods = type(self).legacy_compression_methods
        self.extensions = {ext.extension_type: ext for ext in extensions}

        if len(random) != 32:  # noqa: PLR2004
            e = "random must be exactly 32 bytes longs"
            raise ValueError(e)

        if not cipher_suites:
            e = "cipher suites cannot be empty"
            raise ValueError(e)

        if len(self.extensions) != len(extensions):
            _find_duplicated_extension(extensions)

        if ExtensionType.PRE_SHARED_KEY in self.extensions:
            if extensions[-1].extension_type != ExtensionType.PRE_SHARED_KEY:
                e = "PreSharedKey() must be the last extension of the list"
                raise ValueError(e)
            if ExtensionType.PSK_KEY_EXCHANGE_MODES not in self.extensions:
                e = "missing mandatory extension: PskKeyExchangeModes()"
                raise ValueError(e)


    @classmethod
    def parse_body(cls, stream, **kwargs):
        legacy_version = stream.read_int(2)
        if legacy_version != TLSVersion.TLS_1_2:
            e = f"expected {TLSVersion.TLS_1_2} but {legacy_version} found"
            raise alerts.ProtocolVersion(e)
        legacy_version = TLSVersion(legacy_version)

        random = stream.read_exactly(32)
        legacy_session_id = stream.read_var(1)

        cipher_suites = [
            try_cast(CipherSuites, cipher_suite)
            for cipher_suite in stream.read_listint(2, 2)
        ]

        legacy_compression_methods = stream.read_var(1)
        if legacy_compression_methods != b'\x00':  # "null" compression method
            e = "only the NULL compression method is supported in TLS 1.3"
            raise alerts.IllegalParameter(e)

        extensions = []
        list_stream = SerialIO(stream.read_var(2))
        while not list_stream.is_eof():
            extension = Extension.parse(list_stream, handshake_type=cls.msg_type, **kwargs)
            extensions.append(extension)

        try:
            self = cls(random, cipher_suites, extensions)
        except ValueError as exc:
            raise alerts.IllegalParameter(*exc.args) from exc
        self.legacy_session_id = legacy_session_id
        return self

    def serialize_body(self):
        extensions = b''.join(ext.serialize() for ext in self.extensions.values())

        return b''.join([
            self.legacy_version.to_bytes(2, 'big'),
            self.random,

            len(self.legacy_session_id).to_bytes(1, 'big'),
            self.legacy_session_id,

            (len(self.cipher_suites) * 2).to_bytes(2, 'big'),
            *[cs.to_bytes(2, 'big') for cs in self.cipher_suites],

            len(self.legacy_compression_methods).to_bytes(1, 'big'),
            self.legacy_compression_methods,

            len(extensions).to_bytes(2, 'big'),
            extensions,
        ])
