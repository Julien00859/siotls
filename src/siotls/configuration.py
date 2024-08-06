"""manquer un truc ici"""

import dataclasses
import functools
import logging
import typing
from collections.abc import Sequence

from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes, PublicKeyTypes
from cryptography.x509 import Certificate, CertificateRevocationList
from cryptography.x509.verification import PolicyBuilder, Store

from siotls.iana import (
    ALPNProtocol,
    CertificateType,
    CipherSuites,
    MaxFragmentLengthOctets as MLFOctets,
    NamedGroup,
    SignatureScheme,
)

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class TLSConfiguration:
    """
    Configure allowed values and restrictions for future connections.
    """

    side: typing.Literal['client', 'server']
    """
    Whether this configuration will be used by a client connection or a
    server one.
    """
    _: dataclasses.KW_ONLY

    cipher_suites: Sequence[CipherSuites] = (
        CipherSuites.TLS_CHACHA20_POLY1305_SHA256,
        CipherSuites.TLS_AES_256_GCM_SHA384,
        CipherSuites.TLS_AES_128_GCM_SHA256,
    )
    """
    List the cipher suites that can be used to encrypt data transmitted
    on the wire. The ciphers are ordered server side in decreasing
    preference order, i.e. the prefered cipher suite should be first in
    the list.

    :attr:`TLSNegotiatedConfiguration.cipher_suite` holds the cipher
    suite that have been agreed by both peers.
    """

    key_exchanges: Sequence[NamedGroup] = (
        NamedGroup.x25519,
        NamedGroup.secp256r1,
    )
    """
    List the allowed key exchange algorithm. New connections can only
    be established when both peer support and allow a same key exchange
    algorithm. The algorithms should be ordered server side in
    decreasing preference order, i.e. the prefered algorithm should be
    first in the list.

    The negotiated cipher is stored in
    :attr:`TLSConnection.nconfig.key_exchange`.

    Default: x25519 > secp256r1.
    """

    signature_algorithms: Sequence[SignatureScheme] = (
        SignatureScheme.ed25519,
        SignatureScheme.ed448,
        SignatureScheme.ecdsa_secp256r1_sha256,
        SignatureScheme.ecdsa_secp384r1_sha384,
        SignatureScheme.ecdsa_secp521r1_sha512,
        SignatureScheme.rsa_pss_pss_sha256,
        SignatureScheme.rsa_pss_pss_sha384,
        SignatureScheme.rsa_pss_pss_sha512,
        SignatureScheme.rsa_pss_rsae_sha256,
        SignatureScheme.rsa_pss_rsae_sha384,
        SignatureScheme.rsa_pss_rsae_sha512,
    )
    """
    The list of allowed signature algorithms. The algorithms should be
    ordered in decreasing preference order, i.e. the prefered algorithm
    should be first in the list. The order matters when the server
    and/or client holds several certificates for a same Subject but with
    different Subject Public Key Info.

    The negotiated cipher is stored in
    :attr:`TLSConnection.nconfig.signature_algorithm`.

    Default: EdDSA > ECDSA > RSA-PSS (pss) > RSA-PSS (rsaEncryption),
    each time sha256 > sha384 > sha512.
    """

    trust_store: Store | None = None
    """
    The trust store to use when validating peer x509 certificates, or
    ``None`` to disable x509 validation (unsafe unless
    :attr:`trusted_public_keys` is non empty). The module
    :mod:`siotls.trust_store` provides several functions to facilitate
    building such store.
    """

    revocation_list: CertificateRevocationList | None = None
    """
    The revocation list to use when validating peer x509 certificates,
    or ``None`` to skip matching certificates against this list (unsafe
    unless OCSP is active).
    """

    max_chain_depth: int = 5
    """
    The maximum certificate chain depth. That is, how many certificates
    can be found between the host certificate and the root certificate,
    both included.
    """

    trusted_public_keys: Sequence[PublicKeyTypes] = ()
    """
    A list of public keys that are not subject to x509 validations and
    that are always trusted. Can be used in addition to
    :attr:`trust_store`.

    *Enables :rfc:`7250` (Raw Public Keys). Using this attribute without
    :attr:`trust_store` disallows exchange of x509 certificates.*
    """

    private_key: PrivateKeyTypes | None = None
    """


    **Mandatory** server-side. **Required** client-side for :abbr:`mTLS
    (mutual TLS)`.
    """

    public_key: PublicKeyTypes | None = None
    """
    The public key counter part of :attr:`private_key`.

    *Enables :rfc:`7250` (Raw Public Keys). Using this attribute without
    :attr:`certificate_chain` disallows exchange of x509 certificates.*

    **Mandatory** server-side. **Required** client-side for :abbr:`mTLS
    (mutual TLS)`. *Unless* regular x509 certificates are in use.
    """

    certificate_chain: Sequence[Certificate] | None = None
    """
    The list of certificates that give a chain of trust between the host
    certificate and a root certificate.

    The first certificate in the list must be the certificate of the
    current host. The following certificates each must sign the previous
    one in the list. The last certificate must be signed by a root CA,
    the root CA itself should not be listed.

    **Mandatory** server-side. **Required** client-side for :abbr:`mTLS
    (mutual TLS)`. *Unless* :rfc:`7250` (Raw Public Keys) is in use.
    """

    max_fragment_length: MLFOctets = MLFOctets.MAX_16384
    """
    Negociate :rfc:`6066#section-4` (Maximum Fragment Length)

    The negotiated fragment length is stored in
    :attr:`TLSConnection.nconfig.max_fragment_length`.
    """

    can_echo_heartbeat: bool = True
    """
    Negociate :rfc:`6520` (Heartbeat).

    The negotiated heartbeat options are stored in
    :attr:`TLSConnection.nconfig.can_send_heartbeat` and
    :attr:`TLSConnection.nconfig.can_echo_heartbeat`.
    """

    alpn: Sequence[ALPNProtocol] = ()
    """
    Negociate :rfc:`7301` (Application-Layer Protocol Negociation/ALPN).

    The list of protocols that this application is willing to use once
    the secure TLS connection is established. The protocols should be
    ordered server-side in decreasing preference order, i.e. the
    prefered protocol should be first in the list.

    The negotiated protocol is stored in :attr:`TLSConnection.nconfig.alpn`.
    """

    server_hostnames: Sequence[str] = ()
    """
    Negociate :rfc:`6066#section-3` (Server Name Indication/SNI).

    Allow a single TLS server to serve multiple hosts. Much like the
    Host header for HTTP. The server must provide a certificate for
    every hosts, it can be a single certificate with multiple :abbr:`SAN
    (Server Alternative Name)` entries.

    This attribute is server-side only.
    """

    log_keys: bool = False
    """
    Enable key logging for netword analysis tools such as wireshark.

    Setting this value ``True`` is not enough to enable key logging, the
    ``siotls.keylog`` logger must be configured too.
    """

    @property
    def require_peer_authentication(self):
        return bool(self.trust_store or self.trusted_public_keys)

    @functools.cached_property
    def certificate_types(self):
        types = []  # order is important, x509 must be first
        if self.certificate_chain:
            types.append(CertificateType.X509)
        if self.public_key:
            types.append(CertificateType.RAW_PUBLIC_KEY)
        return types

    @functools.cached_property
    def peer_certificate_types(self):
        types = []  # order is important, x509 must be first
        if self.trust_store:
            types.append(CertificateType.X509)
        if self.trusted_public_keys:
            types.append(CertificateType.RAW_PUBLIC_KEY)
        return types

    @functools.cached_property
    def policy_builder(self):
        return (
            PolicyBuilder()
            .store(self.trust_store)
            .max_chain_depth(self.max_chain_depth)
        )

    @property
    def other_side(self):
        return 'server' if self.side == 'client' else 'client'

    def __post_init__(self):
        self._check_mandatory_settings()
        if self.side == 'server':
            self._check_server_settings()
        else:
            self._check_client_settings()

    def _check_mandatory_settings(self):
        if not self.cipher_suites:
            e = "at least one cipher suite must be provided"
            raise ValueError(e)
        if not self.key_exchanges:
            e = "at least one key exchange must be provided"
            raise ValueError(e)
        if not self.signature_algorithms:
            e = "at least one signature algorithm must be provided"
            raise ValueError(e)

    def _check_server_settings(self):
        if self.max_fragment_length != MLFOctets.MAX_16384:
            e = "max fragment length is only configurable client side"
            raise ValueError(e)
        if not self.private_key:
            e = "a private key is mandatory server side"
            raise ValueError(e)
        if not (self.certificate_chain or self.public_key):
            e = "a certificate or a public key is mandatory server side"
            raise ValueError(e)
        if self.require_peer_authentication:
            m =("a trust store and/or a list of trusted public keys is "
                "provided, client certificates will be requested")
            logger.info(m)

    def _check_client_settings(self):
        if not self.require_peer_authentication:
            w =("missing trust store or list of trusted public keys, "
                "will not verify the peer's authenticity")
            logger.warning(w)
        if self.server_hostnames:
            e =("the configuration's (plural) server_hostnames is "
                "meant for the server side, maybe you intended to use "
                "the connection's (singular) server_hostname instead")
            raise ValueError(e)


# This class is manually documented
@dataclasses.dataclass(init=False)
class TLSNegotiatedConfiguration:
    """ The values agreed by both peers on a specific connection. """

    cipher_suite: CipherSuites | None
    key_exchange: NamedGroup | None
    signature_algorithm: SignatureScheme | None
    alpn: ALPNProtocol | None | type(...)
    can_send_heartbeat: bool | None
    can_echo_heartbeat: bool | None
    max_fragment_length: MLFOctets | None
    client_certificate_type: CertificateType | None
    server_certificate_type: CertificateType | None
    peer_want_ocsp_stapling: bool | None
    peer_certificate: Certificate | None
    peer_public_key: PublicKeyTypes | None

    def __init__(self):
        object.__setattr__(self, '_frozen', False)
        self.cipher_suite = None
        self.key_exchange = None
        self.signature_algorithm = None
        self.alpn = ...  # None is part of the domain, using Ellipsis as "not set" value
        self.can_send_heartbeat = None
        self.can_echo_heartbeat = None
        self.max_fragment_length = None
        self.client_certificate_type = None
        self.server_certificate_type = None
        self.peer_want_ocsp_stapling = None
        self.peer_certificate = None
        self.peer_public_key = None

    def freeze(self):
        self._frozen = True

    def __setattr__(self, attr, value):
        if self._frozen:
            e = f"cannot assign attribute {attr!r}: frozen instance"
            raise TypeError(e)
        super().__setattr__(attr, value)

    def __delattr__(self, attr):
        if self._frozen:
            e = f"cannot delete attribute {attr!r}: frozen instance"
            raise TypeError(e)
        super().__delattr__(attr)
