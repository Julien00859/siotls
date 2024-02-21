import contextlib
import dataclasses
import logging
import textwrap

import idna

from siotls.contents import alerts
from siotls.iana import ExtensionType, HandshakeType, NameType
from siotls.serial import SerialIO, Serializable, SerializableBody

from . import Extension

logger = logging.getLogger(__name__)
_server_name_registry = {}

@dataclasses.dataclass(init=False)
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
    name_type: NameType = dataclasses.field(repr=False)

    def __init_subclass__(cls, *, register=True, **kwargs):
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
            raise alerts.UnrecognizedName from exc

        return cls.parse_body(stream)

    def serialize(self):
        return b''.join([
            self.name_type.to_bytes(1, 'big'),
            self.serialize_body(),
        ])

@dataclasses.dataclass(init=False)
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

@dataclasses.dataclass(init=False)
class ServerNameListRequest(Extension, SerializableBody):
    extension_type = ExtensionType.SERVER_NAME
    _handshake_types = (HandshakeType.CLIENT_HELLO,)
    _struct = textwrap.dedent("""
        struct {
            ServerName server_name_list<1..2^16-1>
        } ServerNameList;
    """).strip('\n')

    server_names: dict[NameType, ServerName]

    def __init__(self, server_name_list: list[ServerName]):
        self.server_names = {}
        for server_name in server_name_list:
            sn = self.server_names.setdefault(server_name.name_type, server_name)
            if sn != server_name:
                e = "there can only be one value per server name type"
                raise alerts.IllegalParameter(e)

    @property
    def host_name(self):
        return self.server_names[NameType.HOST_NAME]

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
            in self.server_names.values()
        ])

        return b''.join([
            len(server_name_list).to_bytes(2, 'big'),
            server_name_list
        ])


@dataclasses.dataclass(init=False)
class ServerNameResponse(Extension, SerializableBody):
    extension_type = ExtensionType.SERVER_NAME
    _handshake_types = (HandshakeType.ENCRYPTED_EXTENSIONS,)
    _struct = r"struct {}"

    def __init__(self):
        pass

    @classmethod
    def parse_body(cls, stream):  # noqa: ARG003
        return cls()

    def serialize_body(self):
        return b''
