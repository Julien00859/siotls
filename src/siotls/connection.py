import logging
import secrets
import struct
import types

from siotls import key_logger
from siotls.ciphers import cipher_suite_registry
from siotls.iana import AlertLevel, ContentType, TLSVersion
from siotls.serial import SerialIO, SerializationError, TooMuchDataError

from .contents import ApplicationData, Content, Handshake, alerts
from .states import ClientStart, ServerStart
from .transcript import Transcript
from .utils import try_cast

logger = logging.getLogger(__name__)
cipher_plaintext = types.SimpleNamespace(
    must_encrypt=False,
    must_decrypt=False,
    should_rekey=False,
)

def startswith_change_cipher_spec(data):
    return data[0:1] == b'\x14' and data[3:6] == b'\x00\x01\x01'


class TLSConnection:
    def __init__(self, config):
        self.config = config
        self.nconfig = None
        self.state = (ClientStart if config.side == 'client' else ServerStart)(self)
        self._cipher = cipher_plaintext
        self._transcript = Transcript({
            cipher_suite_registry[cipher_suite].digestmod
            for cipher_suite in config.cipher_suites
        })

        self._input_data = bytearray()
        self._input_handshake = bytearray()
        self._output_data = bytearray()

        if config.side == 'client':
            self._client_unique = secrets.token_bytes(32)
            self._server_unique = None
        else:
            self._client_unique = None
            self._server_unique = secrets.token_bytes(32)

        self._key_shares = {}
        self._cookie = None

    # ------------------------------------------------------------------
    # Public APIs
    # ------------------------------------------------------------------

    def initiate_connection(self):
        if self.config.log_keys:
            is_key_logger_enabled = any(
                not isinstance(handler, logging.NullHandler)
                for handler in key_logger.handlers
            )
            if is_key_logger_enabled:
                logger.info("Key log enabled for current connection.")
            else:
                logger.warning(
                    "Key log was requested for current connection but no "
                    "logging.Handler seems setup on the %r logger. You must "
                    "setup one.\nlogging.getLogger(%r).addHandler(logging."
                    "FileHandler(path_to_keylogfile, %r))",
                    key_logger.name, key_logger.name, "w")

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
                    raise alerts.DecodeError from exc
                logger.info("received %s", type(content).__name__)
                match content:
                    case alerts.Alert(level=AlertLevel.WARNING):
                        logger.warning(content.description)
                    case alerts.Alert(level=AlertLevel.FATAL):
                        logger.error(content.description)
                        break  # TODO: close
                    case Handshake():
                        self._transcript.update(
                            content_data,
                            self.config.other_side,
                            content.msg_type
                        )
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

        if self._cipher.should_rekey:
            self.rekey()

    def send_data(self, data: bytes):
        self._send_content(ApplicationData(data))

    def data_to_send(self):
        output = self._output_data
        self._output_data = bytearray()
        return output

    def rekey(self):
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Internal APIs
    # ------------------------------------------------------------------

    def _move_to_state(self, state_type):
        self.state = state_type(self)

    @property
    def _max_fragment_length(self):
        if self.nconfig and self.nconfig.max_fragment_length is not None:
            return self.nconfig.max_fragment_length
        return self.config.max_fragment_length

    def _read_next_record(self):
        while startswith_change_cipher_spec(self._input_data):
            self._input_data = self._input_data[6:]

        if len(self._input_data) < 5:  # noqa: PLR2004
            return None

        content_type, _legacy_version, content_length = \
            struct.unpack('!BHH', self._input_data[:5])

        max_fragment_length = self._max_fragment_length
        if self._cipher.must_decrypt:
            max_fragment_length += 256
        if content_length > max_fragment_length:
            e =(f"the record is longer ({content_length} bytes) than "
                f"the allowed maximum ({max_fragment_length} bytes)")
            raise alerts.RecordOverFlow(e)

        if len(self._input_data) - 5 < content_length:
            return None

        header = self._input_data[:5]
        fragment = self._input_data[5:content_length + 5]
        self._input_data = self._input_data[content_length + 5:]
        if self._cipher.must_decrypt:
            content_type, fragment = self._decrypt(header, fragment)

        if content_type == ContentType.CHANGE_CIPHER_SPEC:
            e = f"invalid {ContentType.CHANGE_CIPHER_SPEC} record"
            raise alerts.UnexpectedMessage(e)

        return content_type, fragment

    def _decrypt(self, header, fragment):
        innertext = self._cipher.decrypt(fragment, header)
        for i in range(len(innertext) -1, -1, -1):
            if innertext[i]:
                break
        else:
            e = "missing content type in encrypted record"
            raise alerts.UnexpectedMessage(e)
        return innertext[i], innertext[:i]

    def _read_next_content(self):
        # handshakes can be fragmented over multiple following records,
        # other content types are not subject to fragmentation

        record = self._read_next_record()
        if not record:
            return None

        content_type, fragment = record
        if not self._input_handshake:
            if content_type != ContentType.HANDSHAKE:
                return content_type, fragment
            else:
                self._input_handshake = fragment
        elif content_type != ContentType.HANDSHAKE:
            e =(f"expected {ContentType.HANDSHAKE} continuation record "
                f"but {content_type} found")
            raise alerts.UnexpectedMessage(e)
        else:
            self._input_handshake += fragment

        if len(self._input_handshake) < 4:  # noqa: PLR2004
            return None
        handshake_length = int.from_bytes(self._input_handshake[1:4], 'big')
        while len(self._input_handshake) - 4 < handshake_length:
            record = self._read_next_record()
            if not record:
                return None
            content_type, fragment = record
            if content_type != ContentType.HANDSHAKE:
                e =(f"expected {ContentType.HANDSHAKE} continuation record "
                    f"but {content_type} found")
                raise alerts.UnexpectedMessage(e)
            self._input_handshake += fragment
        if len(self._input_handshake) - 4 > handshake_length:
            e = (f"expected {handshake_length + 4} bytes but "
                 f"{len(self._input_handshake)} read")
            raise TooMuchDataError(e)

        content_data = self._input_handshake
        self._input_handshake = bytearray()
        return content_type, content_data

    def _send_content(self, content: Content):
        logger.info("will send %s", type(content).__name__)
        data = content.serialize()

        if content.content_type == ContentType.HANDSHAKE:
            self._transcript.update(data, self.config.side, content.msg_type)

        fragment_length = self._max_fragment_length
        if self._cipher.must_encrypt:
            # room for content-type and aead's additionnal data
            fragment_length -= 1 + self._cipher.tag_length

        if len(data) <= fragment_length:
            fragments = (data,)
        elif content.can_fragment:
            fragments = (
                data[i : i + fragment_length]
                for i in range(0, len(data), fragment_length)
            )
        else:
            e =(f"serialized {content} ({len(data)} bytes) doesn't fit "
                f"inside a single record (max {fragment_length} bytes) "
                " and cannot be fragmented over multiple ones")
            raise ValueError(e)

        if self._cipher.must_encrypt:
            record_type = ContentType.APPLICATION_DATA
            fragments = self._encrypt(content.content_type, fragments, self._max_fragment_length)
        else:
            record_type = content.content_type

        self._output_data += b''.join(
            b''.join([
                record_type.to_bytes(1, 'big'),
                TLSVersion.TLS_1_2.to_bytes(2, 'big'),  # legacy version
                len(fragment).to_bytes(2, 'big'),
                fragment,
            ])
            for fragment in fragments
        )

    def _encrypt(self, content_type, fragments, max_fragment_length):
        # RFC-8446 doesn't specify anything regarding padding, it only
        # says that it is a good idea. We add padding so that record
        # sizes are a multiple of 4kib (or less if max_fragment_length)
        chunk_size = min(max_fragment_length, 4096)

        for fragment in fragments:
            fragment_length = len(fragment) + 1 + self._cipher.tag_length
            padding = b'\x00' * (chunk_size - fragment_length % chunk_size)
            data = b''.join([
                fragment,
                content_type.to_bytes(1, 'big'),
                padding,
            ])
            header = b''.join([
                ContentType.APPLICATION_DATA.to_bytes(1, 'big'),
                TLSVersion.TLS_1_2.to_bytes(2, 'big'),  # legacy version
                (len(data) + self._cipher.tag_length).to_bytes(2, 'big'),
            ])
            encrypted_fragment = self._cipher.encrypt(data, header)

            assert len(encrypted_fragment) == len(data) + self._cipher.tag_length, \
                (len(encrypted_fragment), len(data), self._cipher.tag_length)  # noqa: S101

            yield encrypted_fragment
