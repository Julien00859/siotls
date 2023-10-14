import dataclasses
import logging
import secrets
import struct
import typing

from siotls.iana import (
    ContentType,
    CipherSuites,
    SignatureScheme,
    NamedGroup,
    ALPNProtocol,
    TLSVersion,
)
from siotls.serial import SerializationError, TooMuchData, SerialIO
from .contents import Content, ApplicationData, alerts
from .states import ClientStart, ServerStart


logger = logging.getLogger(__name__)
SERVER_MAX_FRAGMENT_LENGTH = 16384


def starswith_change_cipher_spec(data):
    return data[0:1] == b'\x14' and data[3:6] == b'\x00\x01\x01'


@dataclasses.dataclass()
class TLSConfiguration:
    side: typing.Literal['client', 'server']

    # mandatory
    cipher_suites: list[CipherSuites | int] = \
        dataclasses.field(default_factory=[
            CipherSuites.TLS_CHACHA20_POLY1305_SHA256,
            CipherSuites.TLS_AES_256_GCM_SHA384,
            CipherSuites.TLS_AES_128_GCM_SHA256,
        ].copy)
    digital_signatures: list[SignatureScheme | int] = \
        dataclasses.field(default_factory=[
            SignatureScheme.rsa_pkcs1_sha256,
            SignatureScheme.rsa_pss_rsae_sha256,
            SignatureScheme.ecdsa_secp256r1_sha256,
        ].copy)
    key_exchanges: list[NamedGroup | int] = \
        dataclasses.field(default_factory=[
            NamedGroup.x25519,
            NamedGroup.secp256r1,
        ].copy)

    # extensions
    max_fragment_length: typing.Literal[
        512, 1024, 2048, 4096, 16384,
    ] = SERVER_MAX_FRAGMENT_LENGTH
    can_send_heartbeat: bool = False
    can_echo_heartbeat: bool = True
    alpn: list[ALPNProtocol] = dataclasses.field(default_factory=list)
    hostnames: list[bytes] = dataclasses.field(default_factory=list)


class TLSConnection:
    def __init__(self, config, **config_changes):
        config = dataclasses.replace(config, **config_changes)
        if config.side == 'server':
            if config.max_fragment_length != SERVER_MAX_FRAGMENT_LENGTH:
                msg = "max fragment length is only configurable client side"
                raise ValueError(msg)

        self.config = config
        self.nconfig = None
        self.state = (ClientStart if config.side == 'client' else ServerStart)(self)

        self._input_data = bytearray()
        self._input_handshake = bytearray()
        self._output_data = bytearray()

        self._nonce = secrets.token_bytes(32)
        self._key_exchange_privkeys = {}

    @property
    def is_encrypted(self):
        return self.nconfig is not None

    @property
    def max_fragment_length(self):
        return (self.nconfig or self.config).max_fragment_length + (
            256 if self.is_encrypted else 0
        )

    #-------------------------------------------------------------------
    # Public APIs
    #-------------------------------------------------------------------

    def initiate_connection(self):
        self.state.initiate_connection()

    def receive_data(self, data):
        if not data:
            return
        self._input_data += data

        while next_content := self._read_next_content():
            content_type, content_data = next_content
            stream = SerialIO(content_data)
            try:
                try:
                    content = Content.get_parser(content_type).parse(stream)
                    stream.assert_eof()
                except SerializationError as exc:
                    raise alerts.DecodeError() from exc
                self.state.process(content)
            except alerts.Alert as alert:
                self._send_content(alert)
                break

    def send_data(self, data: bytes):
        self._send_content(ApplicationData(data))

    def data_to_send(self):
        output = self._output_data
        self._output_data = bytearray()
        return output

    #-------------------------------------------------------------------
    # Internal APIs
    #-------------------------------------------------------------------

    def _move_to_state(self, state_type):
        self.state = state_type(self)

    def _read_next_record(self):
        while starswith_change_cipher_spec(self._input_data):
            self._input_data = self._input_data[6:]

        if len(self._input_data) < 5:
            return

        content_type, _legacy_version, content_length = \
            struct.unpack('!BHH', self._input_data[:5])

        if content_length > self.max_fragment_length:
            msg = (f"The record is longer ({content_length} bytes) than "
                   f"the allowed maximum ({self.max_fragment_length}"
                   " bytes).")
            raise alerts.RecordOverFlow(msg)

        if len(self._input_data) - 5 < content_length:
            return

        fragment = self._input_data[5:content_length + 5]
        self._input_data = self._input_data[content_length + 5:]

        if self.is_encrypted:
            innertext = self.decrypt(fragment)
            for i in range(len(innertext) -1, -1, -1):
                if innertext[i]:
                    break
            else:
                msg = "missing content type in encrypted record"
                raise alerts.UnexpectedMessage(msg)
            content_type = innertext[i]
            fragment = innertext[:i]

        if content_type == ContentType.CHANGE_CIPHER_SPEC:
            msg = f"invalid {ContentType.CHANGE_CIPHER_SPEC} record"
            raise alerts.UnexpectedMessage(msg)

        return content_type, fragment

    def _read_next_content(self):
        # handshakes can be fragmented over multiple following records,
        # other content types are not subject to fragmentation

        record = self._read_next_record()
        if not record:
            return

        content_type, fragment = record
        if not self._input_handshake:
            if content_type != ContentType.HANDSHAKE:
                return content_type, fragment
            else:
                self._input_handshake = fragment
        elif content_type != ContentType.HANDSHAKE:
            msg = (
                f"Expected {ContentType.HANDSHAKE} continuation "
                f"record but {content_type} found."
            )
            raise alerts.UnexpectedMessage(msg)
        else:
            self._input_handshake += fragment

        if len(self._input_handshake) < 4:
            return
        handshake_length = int.from_bytes(self._input_handshake[1:4], 'big')
        while len(self._input_handshake) - 4 < handshake_length:
            record = self._read_next_record()
            if not record:
                return
            content_type, fragment = record
            if content_type != ContentType.HANDSHAKE:
                msg = (f"Expected {ContentType.HANDSHAKE} continuation "
                       f"record but {content_type} found.")
                raise alerts.UnexpectedMessage(msg)
            self._input_handshake += fragment
        if len(self._input_handshake) - 4 > handshake_length:
            msg = (f"Expected {handshake_length + 4} bytes but "
                   f"{len(self._input_handshake)} read.")
            raise TooMuchData(msg)

        content_data = self._input_handshake
        self._input_handshake = bytearray()
        return content_type, content_data

    def _send_content(self, content: Content):
        data = content.serialize()
        if self.is_encrypted:
            data = self.encrypt(data)

        if len(data) < self.max_fragment_length:
            iter_fragments = (data,)
        elif content.can_fragment:
            iter_fragments = (
                data[i : i + self.max_fragment_length]
                for i in range(0, len(data), self.max_fragment_length)
            )
        else:
            msg = (f"Serialized content ({len(data)} bytes) cannot fit "
                   f"in a single record (max {self.max_fragment_length}"
                   " bytes) and cannot be fragmented over multiple TLS"
                   " 1.2 records.")
            raise ValueError(msg)

        self._output_data += b''.join((
            b''.join([
                (
                    ContentType.APPLICATION_DATA
                    if self.is_encrypted else
                    content.content_type
                ).to_bytes(1, 'big'),
                TLSVersion.TLS_1_2.to_bytes(2, 'big'),  # legacy version
                len(fragment).to_bytes(2, 'big'),
                fragment,
            ])
            for fragment in iter_fragments
        ))
