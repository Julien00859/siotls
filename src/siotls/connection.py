import dataclasses
import logging
import struct
import typing

from siotls.iana import (
    ContentType,
    CipherSuites,
    SignatureScheme,
    NamedGroup,
    ALPNProtocol,
)
from siotls.serial import TooMuchData, SerialIO
from .contents import Content, alerts


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
        self._input_data = b''
        self._input_handshake = b''
        self._output_data = b''
        #self.state = (... if self.config.side == 'server' else ...)(self)

    @property
    def is_encrypted(self):
        return self.nconfig is not None

    @property
    def max_fragment_length(self):
        return (self.nconfig or self.config).max_fragment_length + (
            256 if self.is_encrypted else 0
        )


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
        self._input_handshake = b''
        return content_type, content_data


    def _process_contents(contents):
        return contents
        #return []
