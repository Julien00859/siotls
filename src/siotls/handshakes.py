from .iana import CipherSuites, ContentType, HandshakeType, TLSVersion
from .contents import Content
from .extensions import Extension
from .serial import Serializable, SerializableBody, SerialIO
from . import alerts


_handshake_registry = {}

class Handshake(Content, Serializable):
    content_type = ContentType.HANDSHAKE

    # struct {
    #     HandshakeType msg_type;    /* handshake type */
    #     uint24 length;             /* remaining bytes in message */
    #     select (Handshake.msg_type) {
    #         case client_hello:          ClientHello;
    #         case server_hello:          ServerHello;
    #         case end_of_early_data:     EndOfEarlyData;
    #         case encrypted_extensions:  EncryptedExtensions;
    #         case certificate_request:   CertificateRequest;
    #         case certificate:           Certificate;
    #         case certificate_verify:    CertificateVerify;
    #         case finished:              Finished;
    #         case new_session_ticket:    NewSessionTicket;
    #         case key_update:            KeyUpdate;
    #     };
    # } Handshake;
    msg_type: HandshakeType

    def __init_subclass__(cls, register=True, **kwargs):
        super().__init_subclass__(**kwargs)
        if register and Handshake in cls.__bases__:
            _handshake_registry[cls.msg_type] = cls

    @classmethod
    def parse(cls, data):
        stream = SerialIO(data)

        msg_type = stream.read_int(1)
        length = stream.read_int(3)
        try:
            cls = _handshake_registry[HandshakeType(msg_type)]
        except ValueError as exc:
            raise alerts.UnrecognizedName() from exc
        self = cls.parse_body(stream.read_exactly(length))
        if remaining := len(data) - stream.tell():
            raise ValueError(f"Expected end of stream but {remaining} bytes remain.")
        return self

    def serialize(self):
        raise NotImplementedError("todo")


class ClientHello(Handshake, SerializableBody):
    msg_type = HandshakeType.CLIENT_HELLO

    # uint16 ProtocolVersion;
    # opaque Random[32];
    #
    # uint8 CipherSuite[2];    /* Cryptographic suite selector */
    #
    # struct {
    #     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
    #     Random random;
    #     opaque legacy_session_id<0..32>;
    #     CipherSuite cipher_suites<2..2^16-2>;
    #     opaque legacy_compression_methods<1..2^8-1>;
    #     Extension extensions<8..2^16-1>;
    # } ClientHello;
    legacy_version = TLSVersion.TLS_1_2
    random: bytes
    legacy_session_id = b''
    cipher_suites: list
    legacy_compression_methods = b'\x00'  # "null" compression method
    extensions: list[Extension]

    def __init__(self, random_, cipher_suites, extensions):
        self.random = random_
        self.cipher_suites = cipher_suites
        self.extensions = extensions

    @classmethod
    def parse_body(cls, data):
        stream = SerialIO(data)

        legacy_version = stream.read_int(2)
        if legacy_version != TLSVersion.TLS_1_2:
            raise alerts.ProtocolVersion()
        legacy_version = TLSVersion(legacy_version)

        random_ = stream.read_exactly(32)
        legacy_session_id = stream.read_var(1)

        cipher_suites = []
        it = iter(stream.read_var(2))
        for pair in zip(it, it):
            cipher = (pair[0] << 8) + pair[1]
            try:
                cipher_suites.append(CipherSuites(cipher))
            except ValueError:
                cipher_suites.append(cipher)

        legacy_compression_methods = stream.read_var(1)
        if legacy_compression_methods != b'\x00':  # "null" compression method
            raise alerts.IllegalParameter()

        extensions = []
        remaining = stream.read_int(2)
        while remaining > 0:
            with stream.lookahead():
                stream.read_exactly(2, limit=remaining)  # extension_type
                extensions_length = stream.read_int(2, limit=remaining - 2)
            extensions.append(
                Extension.parse(stream.read_exactly(4 + extensions_length, limit=remaining))
            )
            remaining -= extensions_length

        if remaining := len(data) - stream.tell():
            raise ValueError(f"Expected end of stream but {remaining} bytes remain.")

        self = cls(random_, cipher_suites, extensions)
        self.legacy_version = legacy_version
        self.legacy_session_id = legacy_session_id
        self.legacy_compression_methods = legacy_compression_methods
        return self

    def serialize_body(self):
        raise NotImplementedError("todo")


class ServerHello(Handshake, SerializableBody):
    msg_type = HandshakeType.SERVER_HELLO

    # struct {
    #     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
    #     Random random;
    #     opaque legacy_session_id_echo<0..32>;
    #     CipherSuite cipher_suite;
    #     uint8 legacy_compression_method = 0;
    #     Extension extensions<6..2^16-1>;
    # } ServerHello;
    ...


class EndOfEarlyData(Handshake, SerializableBody):
    msg_type = HandshakeType.END_OF_EARLY_DATA
    ...


class EncryptedExtensions(Handshake, SerializableBody):
    msg_type = HandshakeType.ENCRYPTED_EXTENSIONS
    ...


class CertificateRequest(Handshake, SerializableBody):
    msg_type = HandshakeType.CERTIFICATE_REQUEST
    ...


class Certificate(Handshake, SerializableBody):
    msg_type = HandshakeType.CERTIFICATE
    ...


class CertificateVerify(Handshake, SerializableBody):
    msg_type = HandshakeType.CERTIFICATE_VERIFY
    ...


class Finished(Handshake, SerializableBody):
    msg_type = HandshakeType.FINISHED
    ...


class NewSessionTicket(Handshake, SerializableBody):
    msg_type = HandshakeType.NEW_SESSION_TICKET
    ...


class KeyUpdate(Handshake, SerializableBody):
    msg_type = HandshakeType.KEY_UPDATE
    ...
