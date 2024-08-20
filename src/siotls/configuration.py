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
    The TLSConfiguration class provides a comprehensive set of options
    to configure the security parameters for TLS connections, applicable
    to both clients and servers.

    It allows control over the cryptographic elements involved in the
    TLS handshake, including the selection of ciphers, key exchange
    methods, and signature algorithms. It also allows control over
    various TLS extensions such as Server Name Indication (SNI),
    Application-Layer Protocol Negotiation (ALPN) and others.

    On the client-side, the ``trust_store`` and ``revocation_list``
    parameters are recommended. If ``trust_store`` is not set, the
    server certificates will not be verified.

    >>> minimal_client_config = TLSConfiguration(
    >>>     'client',
    >>>     trust_store=build_system_store(),
    >>>     revocation_list=...,
    >>> )

    On the server-side, the ``private_key`` and ``certificate_chain``
    parameters are mandatory.

    >>> minimal_server_config = TLSConfiguration(
    >>>     'server',
    >>>     private_key=...,
    >>>     certificate_chain=...,
    >>> )

    Server authentication is mandatory by TLS. Client authentication
    (mutual TLS) is optional. Set the ``trust_store`` and
    ``revocation_list`` parameters server-side to request client
    authentication. Set the ``private_key`` and ``certificate_chain``
    pair client-side to respond.

    The ``trust_store`` and ``certificate_chain`` parameters are used
    for certificate authentication. Raw public keys can be used in
    addition to / instead of certificates. Set the ``public_key``
    parameter server-side. Set the ``trusted_public_keys`` parameter
    client-side. Set the other parameter on the other side for mutual
    TLS.
    """

    side: typing.Literal['client', 'server']
    """
    Tell whether this configuration will be used for client connections
    or server ones.
    """
    _: dataclasses.KW_ONLY

    cipher_suites: Sequence[CipherSuites] = (
        CipherSuites.TLS_CHACHA20_POLY1305_SHA256,
        CipherSuites.TLS_AES_256_GCM_SHA384,
        CipherSuites.TLS_AES_128_GCM_SHA256,
    )
    """
    List the cipher suites that can be used to encrypt data transmitted
    on the wire.

    If the peers cannot agree on a same cipher suite, the connection
    fails with a :class:`siotls.alerts.HandshakeFailure` fatal alert.

    The list should be ordered server-side in decreasing preference
    order, i.e. the prefered cipher should be first in the list. The
    order doesn't matter client-side.

    The negotiated cipher is available at
    :attr:`TLSNegotiatedConfiguration.cipher_suite`.
    """

    key_exchanges: Sequence[NamedGroup] = (
        NamedGroup.x25519,
        NamedGroup.secp256r1,
    )
    """
    List the allowed key exchange algorithms that can be used to share
    a secret and bootstrap encryption.

    If the peers cannot agree on a same key exchange algorithm, the
    connection fails with a :class:`siotls.alerts.HandshakeFailure`
    fatal alert.

    The list should be ordered server-side in decreasing preference
    order, i.e. the prefered algorithm should be first in the list. The
    order doesn't matter client-side.

    The negotiated algorithm is available at
    :attr:`TLSConnection.nconfig.key_exchange`.
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
    List the signature algorithm allowed in the CertificateVerify TLS
    handshake.

    Typically used to refine what asymetric key algorithms are
    authorized, with what padding and hashing algorithms for new
    signatures. This can be used to allow RSA-PSS-SHA2 but reject
    RSA-PKCS1-SHA1.

    The negotiated algorithm is available at
    :attr:`TLSConnection.nconfig.signature_algorithm`.
    """

    trust_store: Store | None = None
    """
    Make peer authentication mandatory. Allow the peer to authenticate
    using x509 certificates.

    It validates the certificates using the CA/Browser Forum baseline
    requirements for TLS server certificates[^1].

    The trust store to use when validating peer x509 certificates, or
    ``None`` to disable x509 validation (unsafe unless
    :attr:`trusted_public_keys` is non empty). The module
    :mod:`siotls.trust_store` provides several functions to facilitate
    building such store.

    [^1]: https://cabforum.org/working-groups/server/baseline-requirements/documents/
    """

    revocation_list: CertificateRevocationList | None = None
    """
    To use with :attr:`trust_store`, list the certificate that are valid
    by themselves but have been revoked by their issuing certification
    authority.
    """

    max_chain_depth: int = 5
    """
    Limit the length of the peer's certificate chain when authenticating
    via x509 certificate.
    """

    trusted_public_keys: Sequence[PublicKeyTypes] = ()
    """
    Negotiate :rfc:`7250#` (Raw Public Keys).

    Make peer authentication mandatory. Allow the peer to authenticate
    using raw public keys.

    When used in addition to :attr:`trust_store`, it allows the peer to
    authenticate with either x509 (preferred) or raw public keys. When
    used instead of :attr:`trust_store`, it only allows raw public keys
    and will reject x509 certificates with an
    :class:`alerts.UnsupportedCertificate` error.
    """

    private_key: PrivateKeyTypes | None = None
    """
    ...
    """

    public_key: PublicKeyTypes | None = None
    """
    Negotiate :rfc:`7250#` (Raw Public Keys).

    ...

    When used in addition to :attr:`certificate_chain`, it will send
    either the certificate chain, either the public key, depending on
    the peer's negotiated preference. When used instead of
    :attr:`certificate_chain`, it will either send the public key,
    either fail with an :class:`alerts.UnsupportedCertificate` alert,
    depending on the peer's support for raw public keys.
    """

    certificate_chain: Sequence[Certificate] | None = None
    """
    The list of certificates that together form a chain of trust between
    the host certificate and a root certificate. Make this side
    authentication possible using x509 certificates.

    The first certificate in the list must be the certificate of the
    current host. The following certificates each must sign the previous
    one in the list. The last certificate must be signed by a root CA,
    the root CA itself should not be listed.
    """

    max_fragment_length: MLFOctets = MLFOctets.MAX_16384
    """
    Negociate :rfc:`6066#section-4` (Maximum Fragment Length)

    Limit the length of data encapsuled by TLS, fragmenting the data
    over multiple records when necessary. The limit only accounts for
    the fragment length and does not account for the additional 5 bytes
    record header.

    This doesn't limit the size of the internal buffers used by siotls
    which can grow up to 24 MiB during handshake after defragmentation.

    The negotiated length is available at
    :attr:`TLSNegotiatedConfiguration.max_fragment_length`.
    """

    can_echo_heartbeat: bool = True
    """
    Negociate :rfc:`6520#` (Heartbeat).

    ...

    The negotiated heartbeat options is available at
    :attr:`TLSNegotiatedConfiguration.can_send_heartbeat` and
    :attr:`TLSNegotiatedConfiguration.can_echo_heartbeat`.
    """

    alpn: Sequence[ALPNProtocol] = ()
    """
    Negociate :rfc:`7301#` (Application-Layer Protocol Negociation/ALPN).

    List the protocols that this application is willing to use once the
    connection is secured.

    The list should be ordered server-side in decreasing preference
    order, i.e. the prefered protocol should be first in the list.

    The negotiated protocol is available at
    :attr:`TLSNegotiatedConfiguration.alpn`.
    """

    server_hostnames: Sequence[str] = ()
    """
    Negociate :rfc:`6066#section-3` (Server Name Indication/SNI).

    Allow a single TLS server to serve multiple hosts. Much like the
    Host header for HTTP. The certificate must be appropriate for all
    hosts.

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
