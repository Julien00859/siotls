from .iana import AlertLevel, AlertDescription, ContentType
from .serial import SerialIO, Serializable
from .contents import Content


_alert_registry = {}

class Alert(Exception, Content, Serializable):
    content_type = ContentType.ALERT

    # enum { warning(1), fatal(2), (255) } AlertLevel;
    #
    # enum {
    #     close_notify(0),
    #     unexpected_message(10),
    #     bad_record_mac(20),
    #     record_overflow(22),
    #     handshake_failure(40),
    #     bad_certificate(42),
    #     unsupported_certificate(43),
    #     certificate_revoked(44),
    #     certificate_expired(45),
    #     certificate_unknown(46),
    #     illegal_parameter(47),
    #     unknown_ca(48),
    #     access_denied(49),
    #     decode_error(50),
    #     decrypt_error(51),
    #     protocol_version(70),
    #     insufficient_security(71),
    #     internal_error(80),
    #     inappropriate_fallback(86),
    #     user_canceled(90),
    #     missing_extension(109),
    #     unsupported_extension(110),
    #     unrecognized_name(112),
    #     bad_certificate_status_response(113),
    #     unknown_psk_identity(115),
    #     certificate_required(116),
    #     no_application_protocol(120),
    #     (255)
    # } AlertDescription;
    #
    # struct {
    #     AlertLevel level;
    #     AlertDescription description;
    # } Alert;


    level: AlertLevel
    description: AlertDescription

    def __init__(self, message='', level=None, description=None):
        super().__init__(message, level, description)
        self.level = level or type(self).level
        self.description = description or type(self).description

    def __init_subclass__(cls, register=True, **kwargs):
        super().__init_subclass__(**kwargs)
        if register and Alert in cls.__bases__:
            _alert_registry[cls.description] = cls

    @classmethod
    def parse(cls, data):
        stream = SerialIO(data)
        level = stream.read_int(1)
        description = stream.read_int(1)
        if remaining := len(data) - stream.tell():
            raise ValueError(f"Expected end of stream but {remaining} bytes remain.")
        return cls('', level, description)

    def serialize(self):
        return ((self.level << 8) + self.description).to_bytes('big')


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


class MissingExtension(Alert):
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
