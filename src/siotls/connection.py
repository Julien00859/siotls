import dataclasses
import logging
import secrets
import struct

from siotls import key_logger
from siotls.iana import (
    AlertLevel,
    ContentType,
    TLSVersion,
)
from siotls.serial import SerializationError, TooMuchData, SerialIO
from .contents import Content, ApplicationData, alerts
from .contents.handshakes import ClientHello, ServerHello
from .states import ClientStart, ServerStart
from .utils import try_cast


logger = logging.getLogger(__name__)

def starswith_change_cipher_spec(data):
    return data[0:1] == b'\x14' and data[3:6] == b'\x00\x01\x01'


class TLSConnection:
    def __init__(self, config, **config_changes):
        config = dataclasses.replace(config, **config_changes)
        config.validate()

        self.config = config
        self.nconfig = None
        self._secrets = None
        self.state = (ClientStart if config.side == 'client' else ServerStart)(self)

        self._input_data = bytearray()
        self._input_handshake = bytearray()
        self._output_data = bytearray()

        if config.side == 'client':
            self._client_nonce = secrets.token_bytes(32)
            self._server_nonce = None
        else:
            self._client_nonce = None
            self._server_nonce = secrets.token_bytes(32)

        self._key_exchange_privkeys = {}
        self._cookie = None

        self._transcript_hash = None
        # RFC 8446 4.4.1 shenanigans regarding HelloRetryRequest
        self._last_client_hello = None
        self._last_server_hello = None

        self._read_cipher = None
        self._read_nonce = None

        self._write_cipher = None
        self._write_nonce = None

        if config.log_keys:
            is_key_logger_enabled = any((
                not isinstance(handler, logging.NullHandler)
                for handler in key_logger.handlers
            ))
            if is_key_logger_enabled:
                logger.info("Key log enabled for current connection.")
            else:
                logger.warning(
                    "Key log was requested for current connection but no "
                    "logging.Handler seems setup on the %r logger. You "
                    "must setup one.\n"
                    "logging.getLogger(%r).addHandler(logging.FileHandler(path_to_keylogfile))",
                    self, key_logger.name, key_logger.name)

    # ------------------------------------------------------------------
    # Public APIs
    # ------------------------------------------------------------------

    def initiate_connection(self):
        self.state.initiate_connection()

    def receive_data(self, data):
        if not data:
            return
        self._input_data += data

        while next_content := self._read_next_content():
            content_type, content_data = next_content
            content_type = try_cast(ContentType, content_type)
            stream = SerialIO(content_data)
            try:
                try:
                    content = Content.get_parser(content_type).parse(stream)
                    stream.assert_eof()
                except SerializationError as exc:
                    raise alerts.DecodeError() from exc
                logger.info("receive %s", content.__class__.__name__)
                match content:
                    case alerts.Alert(level=AlertLevel.WARNING):
                        logger.warning(content.description)
                    case alerts.Alert(level=AlertLevel.FATAL):
                        logger.error(content.description)
                        break  # TODO: close
                    case ClientHello():
                        self._last_client_hello = content_data
                        self.state.process(content)
                    case ServerHello():
                        self._last_server_hello = content_data
                        self.state.process(content)
                    case _:
                        self.state.process(content)
            except alerts.Alert as alert:
                if alert.level == AlertLevel.WARNING:
                    logger.warning("while processing %s: %s", content_type, alert)
                else:
                    logger.exception("while processing %s", content_type)
                self._send_content(alert)
                break  # TODO: close
            except Exception:
                logger.exception("while processing %s", content_type)
                self._send_content(alerts.InternalError())
                break  # TODO: close

    def send_data(self, data: bytes):
        self._send_content(ApplicationData(data))

    def data_to_send(self):
        output = self._output_data
        self._output_data = bytearray()
        return output

    def rekey(self):
        raise NotImplementedError("todo")

    # ------------------------------------------------------------------
    # Internal APIs
    # ------------------------------------------------------------------

    def _move_to_state(self, state_type):
        self.state = state_type(self)

    def _read_next_record(self):
        while starswith_change_cipher_spec(self._input_data):
            self._input_data = self._input_data[6:]

        if len(self._input_data) < 5:
            return

        content_type, _legacy_version, content_length = \
            struct.unpack('!BHH', self._input_data[:5])

        max_fragment_length = (self.nconfig or self.config).max_fragment_length
        if self._read_cipher:
            max_fragment_length += 256
        if content_length > max_fragment_length:
            e =(f"The record is longer ({content_length} bytes) than "
                f"the allowed maximum ({max_fragment_length} bytes).")
            raise alerts.RecordOverFlow(e)

        if len(self._input_data) - 5 < content_length:
            return

        header = self._input_data[:5]
        fragment = self._input_data[5:content_length + 5]
        self._input_data = self._input_data[content_length + 5:]

        if self._read_cipher:
            innertext = self._read_cipher.decrypt(
                nonce=next(self._read_nonce),
                data=fragment,
                associated_data=header,
            )
            for i in range(len(innertext) -1, -1, -1):
                if innertext[i]:
                    break
            else:
                e = "missing content type in encrypted record"
                raise alerts.UnexpectedMessage(e)
            content_type = innertext[i]
            fragment = innertext[:i]

        if content_type == ContentType.CHANGE_CIPHER_SPEC:
            e = f"invalid {ContentType.CHANGE_CIPHER_SPEC} record"
            raise alerts.UnexpectedMessage(e)

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
            e =(f"Expected {ContentType.HANDSHAKE} continuation record "
                f"but {content_type} found.")
            raise alerts.UnexpectedMessage(e)
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
                e =(f"Expected {ContentType.HANDSHAKE} continuation record "
                    f"but {content_type} found.")
                raise alerts.UnexpectedMessage(e)
            self._input_handshake += fragment
        if len(self._input_handshake) - 4 > handshake_length:
            e = (f"Expected {handshake_length + 4} bytes but "
                 f"{len(self._input_handshake)} read.")
            raise TooMuchData(e)

        content_data = self._input_handshake
        self._input_handshake = bytearray()
        if self._transcript_hash:
            self._transcript_hash.update(content_data)
        return content_type, content_data

    def _reset_nonces(self, read_iv, write_iv):
        read_iv = int.from_bytes(read_iv, 'big')
        write_iv = int.from_bytes(write_iv, 'big')
        max_sequence = self.nconfig.cipher_suite.max_sequence
        nonce_length = self.nconfig.cipher_suite.nonce_length
        rekey_threshold = max_sequence * .99

        self._read_nonce = (
            (read_iv ^ read_sequence).to_bytes(nonce_length, 'big')
            for read_sequence in range(max_sequence)
        )
        self._write_nonce = (
            (
                (write_iv ^ write_sequence).to_bytes(nonce_length, 'big'),
                write_sequence >= rekey_threshold,  # should_rekey
            )
            for write_sequence in range(max_sequence)
        )

    def _send_content(self, content: Content):
        logger.info("will send %s", content.__class__.__name__)
        data = content.serialize()

        if self._transcript_hash and content.content_type == ContentType.HANDSHAKE:
            self._transcript_hash.update(data)
        match content:
            case ClientHello():
                self._last_client_hello = data
            case ServerHello():
                self._last_server_hello = data

        fragment_length = (self.nconfig or self.config).max_fragment_length
        if self._write_cipher:
            fragment_length -= 1  # room for content_type, see _encrypt()

        if len(data) <= fragment_length:
            fragments = (data,)
        elif content.can_fragment:
            fragments = (
                data[i : i + fragment_length]
                for i in range(0, len(data), fragment_length)
            )
        else:
            e =(f"Serialized {content} ({len(data)} bytes) doesn't fit "
                f"inside a single record (max {fragment_length} bytes) "
                " and cannot be fragmented over multiple ones.")
            raise ValueError(e)

        if self._write_cipher:
            record_type = ContentType.APPLICATION_DATA
            fragments = self._encrypt(content.content_type, fragments, fragment_length)
        else:
            record_type = ContentType.content_type

        self._output_data += b''.join(
            b''.join([
                record_type.to_bytes(1, 'big'),
                TLSVersion.TLS_1_2.to_bytes(2, 'big'),  # legacy version
                len(fragment).to_bytes(2, 'big'),
                fragment,
            ])
            for fragment in fragments
        )

    def _encrypt(self, content_type, fragments, fragment_length):
        tag_length = self.nconfig.cipher_suite.tag_length

        # RFC-8446 doesn't specify anything regarding padding, it only
        # says that it is a good idea. We add padding so that record
        # sizes are a multiple of 4kib (or less if max_fragment_lenght)
        chunk_size = min(fragment_length, 4096)
        def padding(data):
            return b'\x00' * (chunk_size - (len(data) - 1) % chunk_size)

        for fragment in fragments:
            encrypted_fragment = self._write_cipher.encrypt(
                nonce=next(self._write_nonce),
                data=b''.join([
                    fragment,
                    content_type.to_bytes(1, 'big'),
                    padding(fragment),
                ]),
                associated_data=b''.join([
                    ContentType.APPLICATION_DATA.to_bytes(1, 'big'),
                    TLSVersion.TLS_1_2.to_bytes(2, 'big'),  # legacy version
                    (len(fragment) + tag_length).to_bytes(2, 'big'),
                ]),
            )
            assert len(encrypted_fragment) == len(fragment) + tag_length
            yield encrypted_fragment
