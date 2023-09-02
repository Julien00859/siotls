import contextlib
import logging
import textwrap
import idna
from siotls.iana import ExtensionType, HandshakeType as HT, NameType
from siotls.serial import Serializable, SerializableBody, SerialIO
from . import Extension
from ..contents import alerts


logger = logging.getLogger(__name__)
_server_name_registry = {}

class ServerName(Serializable):
    _struct = textwrap.dedent("""
        struct {
            NameType name_type;
            select (name_type) {
                case host_name: HostName;
            } name;
        } ServerName;

        enum {
            host_name(0x00), (0xff)
        } NameType;
    """).strip('\n')
    name_type: NameType

    def __init_subclass__(cls, register=True, **kwargs):
        super().__init_subclass__(**kwargs)
        if register and ServerName in cls.__bases__:
            _server_name_registry[cls.name_type] = cls

    @classmethod
    def parse(abc, stream):
        name_type = stream.read_int(1)
        try:
            cls = _server_name_registry[NameType(name_type)]
        except ValueError as exc:
            # unknown type, can choice to either crash or ignore
            # this extension, crash for now.
            # should be configurable (should it?)
            raise alerts.UnrecognizedName() from exc

        return cls.parse_body(stream)

    def serialize(self):
        return b''.join([
            self.name_type.to_bytes(1, 'big'),
            self.serialize_body(),
        ])

class HostName(ServerName, SerializableBody):
    name_type = NameType.HOST_NAME

    _struct = textwrap.dedent("""
        opaque HostName<1..2^16-1>;
    """).strip('\n')
    host_name: str

    def __init__(self, host_name):
        self.host_name = host_name

    @classmethod
    def parse_body(cls, stream):
        byte_host_name = stream.read_var(2)
        try:
            return cls(idna.decode(byte_host_name))
        except idna.IDNAError as exc:
            logger.warning("Skip invalid hostname %s: %s", byte_host_name, exc)
            raise

    def serialize_body(self):
        return b''.join([
            len(self.host_name).to_bytes(2, 'big'),
            idna.encode(self.host_name, uts46=True),
        ])

class ServerNameList(Extension, SerializableBody):
    extension_type = ExtensionType.SERVER_NAME
    _handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}
    _struct = textwrap.dedent("""
        struct {
            ServerName server_name_list<1..2^16-1>
        } ServerNameList;
    """).strip('\n')

    server_name_list: list[ServerName]

    def __init__(self, server_name_list):
        self.server_name_list = server_name_list

    @classmethod
    def parse_body(cls, stream):
        server_name_list = []
        list_stream = SerialIO(stream.read_var(2))
        while not list_stream.is_eof():
            with contextlib.suppress(UnicodeError):
                server_name = ServerName.parse(list_stream)
                server_name_list.append(server_name)
        return cls(server_name_list)

    def serialize_body(self):
        server_name_list = b''.join([
            server_name.serialize()
            for server_name
            in self.server_name_list
        ])

        return b''.join([
            len(server_name_list).to_bytes(2, 'big'),
            server_name_list
        ])
