import dataclasses
import typing
import logging
import struct

from siotls.iana import (
    TLSVersion,
    ContentType,
    CipherSuites,
    SignatureScheme,
    NamedGroup,
    ALPNProtocol,
    MaxFragmentLength,
)
from siotls.serial import TooMuchData, SerialIO
from .contents import Content, ApplicationData, alerts
from .states import ClientStart, ServerStart


logger = logging.getLogger(__name__)
DEFAULT_MAX_FRAGMENT_LENGTH = 16384


@dataclasses.dataclass(frozen=True)
class TLSConfiguration:
    side: typing.Literal['client', 'server']

    # mandatory
    cipher_suites: list[CipherSuites | int] = [
        CipherSuites.TLS_CHACHA20_POLY1305_SHA256,
        CipherSuites.TLS_AES_256_GCM_SHA384,
        CipherSuites.TLS_AES_128_GCM_SHA256,
    ]
    digital_signatures: list[SignatureScheme | int] = [
        SignatureScheme.rsa_pkcs1_sha256,
        SignatureScheme.rsa_pss_rsae_sha256,
        SignatureScheme.ecdsa_secp256r1_sha256,
    ]
    key_exchanges: list[NamedGroup | int] = [
        NamedGroup.x25519,
        NamedGroup.secp256r1,
    ]

    # extensions
    max_fragment_length: typing.Literal[
        MaxFragmentLength.LIMIT_512,
        MaxFragmentLength.LIMIT_1024,
        MaxFragmentLength.LIMIT_2048,
        MaxFragmentLength.LIMIT_4096,
        DEFAULT_MAX_FRAGMENT_LENGTH,
    ] = DEFAULT_MAX_FRAGMENT_LENGTH
    can_send_heartbeat: bool = False
    can_echo_heartbeat: bool = True
    alpn: list[ALPNProtocol] | None = None



@dataclasses.dataclass(frozen=True)
class TLSNegociation:
    cipher_suite: CipherSuites
    digital_signature: SignatureScheme
    key_exchange: NamedGroup
    alpn: ALPNProtocol | None
    can_send_heartbeat: bool
    can_echo_heartbeat: bool
    max_fragment_length: int


class TLSConnection:
    def __init__(self, config):
        self.config = config
        self.nconfig = None
        self._input_data = b''
        self._input_handshake = b''
        self._output_data = b''

        self.state = (
            ClientStart(self)
            if self.config.side == 'client' else
            ServerStart(self)
        )

    @property
    def is_encrypted(self):
        return self.state.is_encrypted

    @property
    def max_fragment_length(self):
        return (
            self.nconfig.max_fragment_length
            if self.nconfig else
            DEFAULT_MAX_FRAGMENT_LENGTH
        ) + (256 if self.is_encrypted else 0)

    def receive_data(self, data):
        if not data:
            return
        self._input_data += data

        contents = []
        for content_type, content_data in iter(self._read_next_content, None):
            stream = SerialIO(content_data)
            content = Content.get_parser(content_type).parse(stream)
            stream.assert_eof()
            contents.append(content)

        return contents

    def data_to_send(self):
        output = self._output_data
        self._output_data = b''
        return output

    def send_data(self, data: bytes):
        self._send_content(ApplicationData(data))

    def _send_content(self, content: Content):
        data = (
            self.encrypt(content)
            if self.is_encrypted else
            content.serialize()
        )

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
            b''.join(
                (
                    ContentType.APPLICATION_DATA
                    if self.is_encrypted else
                    content.msg_type
                ).to_bytes(1, 'big'),
                TLSVersion.TLS_1_2.to_bytes(2, 'big'),  # legacy version
                len(fragment).to_bytes(2, 'big'),
                fragment,
            )
            for fragment in iter_fragments
        ))

    def _read_next_record(self):
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

        if not self.is_encrypted or content_type == ContentType.CHANGE_CIPHER_SPEC:
            return content_type, fragment

        innertext = self.decrypt(fragment)
        for i in range(len(innertext) -1, -1, -1):
            if innertext[i]:
                break
        else:
            return  # only padding

        content_type = innertext[i]
        fragment = innertext[:i-1]
        if content_type == ContentType.CHANGE_CIPHER_SPEC:
            msg = f"cannot receive encrypted {ContentType.CHANGE_CIPHER_SPEC}"
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
        self._input_handshake = b''
        return content_type, content_data
