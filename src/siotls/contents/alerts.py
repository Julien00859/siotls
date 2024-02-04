import dataclasses
import textwrap
import typing

from siotls.iana import AlertDescription, AlertLevel, ContentType
from siotls.serial import Serializable

from . import Content

_alert_registry = {}

@dataclasses.dataclass(init=False)
class Alert(Exception, Content, Serializable):  # noqa: N818
    content_type = ContentType.ALERT
    can_fragment = False

    _struct = textwrap.dedent("""
        struct {
            AlertLevel level;
            AlertDescription description;
            select (Alert.level) {
                case 0x00: CloseNotify;
                case 0x0a: UnexpectedMessage;
                case 0x14: BadRecordMac;
                case 0x16: RecordOverflow;
                case 0x28: HandshakeFailure;
                case 0x2a: BadCertificate;
                case 0x2b: UnsupportedCertificate;
                case 0x2c: CertificateRevoked;
                case 0x2d: CertificateExpired;
                case 0x2e: CertificateUnknown;
                case 0x2f: IllegalParameter;
                case 0x30: UnknownCa;
                case 0x31: AccessDenied;
                case 0x32: DecodeError;
                case 0x33: DecryptError;
                case 0x46: ProtocolVersion;
                case 0x47: InsufficientSecurity;
                case 0x50: InternalError;
                case 0x56: InappropriateFallback;
                case 0x5a: UserCanceled;
                case 0x6d: MissingExtension;
                case 0x6e: UnsupportedExtension;
                case 0x70: UnrecognizedName;
                case 0x71: BadCertificateStatusResponse;
                case 0x73: UnknownPskIdentity;
                case 0x74: CertificateRequired;
                case 0x78: NoApplicationProtocol;
                case    _: UnknownAlert;
            };
        } Alert;
    """).strip('\n')
    args: tuple[typing.Any]
    level: AlertLevel
    description: AlertDescription | int

    def __init__(self, *args, level=None):
        super().__init__(*args)
        self.level = level or type(self).level

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if Alert in cls.__bases__:
            _alert_registry[cls.description] = cls

    @classmethod
    def parse(abc, stream):
        try:
            level = AlertLevel(stream.read_int(1))
        except ValueError as exc:
            raise IllegalParameter from exc
        description = stream.read_int(1)

        try:
            cls = _alert_registry[AlertDescription(description)]
        except ValueError:
            cls = type(f'UnknownAlert{description}', (Alert,), {
                'level': level,
                'description': description,
                '_struct': '',
            })

        return cls('', level)

    def serialize(self):
        return ((self.level << 8) + self.description).to_bytes(2, 'big')


class CloseNotify(Alert):
    """
    This alert notifies the recipient that the sender will not send any
    more messages on this connection.  Any data received after a closure
    alert has been received MUST be ignored.
    """
    level = AlertLevel.FATAL
    description = AlertDescription.CLOSE_NOTIFY


class UnexpectedMessage(Alert):
    """
    An inappropriate message (e.g., the wrong handshake message,
    premature Application Data, etc.) was received. This alert should
    never be observed in communication between proper implementations.
    """
    level = AlertLevel.FATAL
    description = AlertDescription.UNEXPECTED_MESSAGE


class BadRecordMac(Alert):
    """
    This alert is returned if a record is received which cannot be
    deprotected.  Because AEAD algorithms combine decryption and
    verification, and also to avoid side-channel attacks, this alert is
    used for all deprotection failures.  This alert should never be
    observed in communication between proper implementations, except
    when messages were corrupted in the network.
    """
    level = AlertLevel.FATAL
    description = AlertDescription.BAD_RECORD_MAC


class RecordOverflow(Alert):
    """
    A TLSCiphertext record was received that had a length more than 2^14
    + 256 bytes, or a record decrypted to a TLSPlaintext record with
    more than 2^14 bytes (or some other negotiated limit).  This alert
    should never be observed in communication between proper
    implementations, except when messages were corrupted in the network.
    """
    level = AlertLevel.FATAL
    description = AlertDescription.RECORD_OVERFLOW


class HandshakeFailure(Alert):
    """
    Receipt of a "handshake_failure" alert message indicates that the
    sender was unable to negotiate an acceptable set of security
    parameters given the options available.
    """
    level = AlertLevel.FATAL
    description = AlertDescription.HANDSHAKE_FAILURE


class BadCertificate(Alert):
    """
    A certificate was corrupt, contained signatures that did not verify
    correctly, etc.
    """
    level = AlertLevel.FATAL
    description = AlertDescription.BAD_CERTIFICATE


class UnsupportedCertificate(Alert):
    """ A certificate was of an unsupported type. """
    level = AlertLevel.FATAL
    description = AlertDescription.UNSUPPORTED_CERTIFICATE


class CertificateRevoked(Alert):
    """ A certificate was revoked by its signer. """
    level = AlertLevel.FATAL
    description = AlertDescription.CERTIFICATE_REVOKED


class CertificateExpired(Alert):
    """ A certificate has expired or is not currently valid. """
    level = AlertLevel.FATAL
    description = AlertDescription.CERTIFICATE_EXPIRED


class CertificateUnknown(Alert):
    """
    Some other (unspecified) issue arose in processing the certificate,
    rendering it unacceptable.
    """
    level = AlertLevel.FATAL
    description = AlertDescription.CERTIFICATE_UNKNOWN


class IllegalParameter(Alert):
    """
    A field in the handshake was incorrect or inconsistent with other
    fields.  This alert is used for errors which conform to the formal
    protocol syntax but are otherwise incorrect.
    """
    level = AlertLevel.FATAL
    description = AlertDescription.ILLEGAL_PARAMETER


class UnknownCa(Alert):
    """
    A valid certificate chain or partial chain was received, but the
    certificate was not accepted because the CA certificate could not be
    located or could not be matched with a known trust anchor.
    """
    level = AlertLevel.FATAL
    description = AlertDescription.UNKNOWN_CA


class AccessDenied(Alert):
    """
    A valid certificate or PSK was received, but when access control was
    applied, the sender decided not to proceed with negotiation.
    """
    level = AlertLevel.FATAL
    description = AlertDescription.ACCESS_DENIED


class DecodeError(Alert):
    """
    A message could not be decoded because some field was out of the
    specified range or the length of the message was incorrect.  This
    alert is used for errors where the message does not conform to the
    formal protocol syntax.  This alert should never be observed in
    communication between proper implementations, except when messages
    were corrupted in the network.
    """
    level = AlertLevel.FATAL
    description = AlertDescription.DECODE_ERROR


class DecryptError(Alert):
    """
    A handshake (not record layer) cryptographic operation failed,
    including being unable to correctly verify a signature or validate a
    Finished message or a PSK binder.
    """
    level = AlertLevel.FATAL
    description = AlertDescription.DECRYPT_ERROR


class ProtocolVersion(Alert):
    """
    The protocol version the peer has attempted to negotiate is
    recognized but not supported (see RFC8446 Appendix D)
    """
    level = AlertLevel.FATAL
    description = AlertDescription.PROTOCOL_VERSION


class InsufficientSecurity(Alert):
    """
    Returned instead of "handshake_failure" when a negotiation has
    failed specifically because the server requires parameters more
    secure than those supported by the client.
    """
    level = AlertLevel.FATAL
    description = AlertDescription.INSUFFICIENT_SECURITY


class InternalError(Alert):
    """
    An internal error unrelated to the peer or the correctness of the
    protocol (such as a memory allocation failure) makes it impossible
    to continue.
    """
    level = AlertLevel.FATAL
    description = AlertDescription.INTERNAL_ERROR


class InappropriateFallback(Alert):
    """
    Sent by a server in response to an invalid connection retry attempt
    from a client (see RFC7507).
    """
    level = AlertLevel.FATAL
    description = AlertDescription.INAPPROPRIATE_FALLBACK


class UserCanceled(Alert):
    """
    This alert notifies the recipient that the sender is canceling the
    handshake for some reason unrelated to a protocol failure.  If a
    user cancels an operation after the handshake is complete, just
    closing the connection by sending a "close_notify" is more
    appropriate.  This alert SHOULD be followed by a "close_notify".
    This alert generally has AlertLevel=warning.
    """
    level = AlertLevel.WARNING
    description = AlertDescription.USER_CANCELED


class MissingExtension(KeyError, Alert):  # noqa: N818
    """
    Sent by endpoints that receive a handshake message not containing an
    extension that is mandatory to send for the offered TLS version or
    other negotiated parameters.
    """
    level = AlertLevel.FATAL
    description = AlertDescription.MISSING_EXTENSION


class UnsupportedExtension(Alert):
    """
    Sent by endpoints receiving any handshake message containing an
    extension known to be prohibited for inclusion in the given
    handshake message, or including any extensions in a ServerHello or
    Certificate not first offered in the corresponding ClientHello or
    CertificateRequest.
    """
    level = AlertLevel.FATAL
    description = AlertDescription.UNSUPPORTED_EXTENSION


class UnrecognizedName(Alert):
    """
    Sent by servers when no server exists identified by the name
    provided by the client via the "server_name" extension (see
    RFC6066).
    """
    level = AlertLevel.FATAL
    description = AlertDescription.UNRECOGNIZED_NAME


class BadCertificateStatusResponse(Alert):
    """
    Sent by clients when an invalid or unacceptable OCSP response is
    provided by the server via the "status_request" extension (see
    RFC6066).
    """
    level = AlertLevel.FATAL
    description = AlertDescription.BAD_CERTIFICATE_STATUS_RESPONSE


class UnknownPskIdentity(Alert):
    """
    Sent by servers when PSK key establishment is desired but no
    acceptable PSK identity is provided by the client. Sending this
    alert is OPTIONAL; servers MAY instead choose to send a
    "decrypt_error" alert to merely indicate an invalid PSK identity.
    """
    level = AlertLevel.FATAL
    description = AlertDescription.UNKNOWN_PSK_IDENTITY


class CertificateRequired(Alert):
    """
    Sent by servers when a client certificate is desired but none was
    provided by the client.
    """
    level = AlertLevel.FATAL
    description = AlertDescription.CERTIFICATE_REQUIRED


class NoApplicationProtocol(Alert):
    """
    Sent by servers when a client "application_layer_protocol_negotiation"
    extension advertises only protocols that the server does not support
    (see RFC7301).
    """
    level = AlertLevel.FATAL
    description = AlertDescription.NO_APPLICATION_PROTOCOL
