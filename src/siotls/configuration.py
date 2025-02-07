import dataclasses
import functools
import logging
import typing
from collections.abc import Sequence

from cryptography.x509.verification import PolicyBuilder, Store
from pyasn1_modules.rfc5280 import (
    Certificate,
    CertificateList,
    SubjectPublicKeyInfo,
)
from pyasn1_modules.rfc5958 import PrivateKeyInfo

import siotls.x509.loader as x509loader
from siotls.crypto import TLSSignatureScheme
from siotls.iana import (
    ALPNProtocol,
    CertificateType,
    CipherSuites,
    MaxFragmentLengthOctets as MLFOctets,
    NamedGroup,
    SignatureScheme,
)
from siotls.services import CRLService, CRTService, OCSPService

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

    **Client** On the client-side, the ``trust_store`` and either
    ``crl_service`` either ``ocsp_service`` and ``cert_service``
    parameters are recommended. If ``trust_store`` is not set, the
    server certificates will not be verified. It the services are not
    set, online certificate revocation check will not be performed.

    >>> minimal_client_config = TLSConfiguration(
    >>>     'client',
    >>>     trust_store=...,
    >>>     ocsp_service=...,
    >>>     cert_service=...,
    >>>     crl_service=...,
    >>> )

    **Server** On the server-side, the ``private_key`` and ``certificate_chain``
    parameters are mandatory.

    >>> minimal_server_config = TLSConfiguration(
    >>>     'server',
    >>>     private_key=...,
    >>>     certificate_chain=...,
    >>> )

    **Mutual TLS** Server authentication is mandatory by TLS. Client
    authentication (mutual TLS) is optional. Set the ``trust_store``
    parameter server-side to request client authentication. Set the
    ``private_key`` and ``certificate_chain`` pair client-side to comply.

    **Raw Public Keys** The ``trust_store`` and ``certificate_chain``
    parameters are used for certificate authentication. It is possible
    to use raw public keys in addition to / instead of certificates. Set
    the ``public_key`` parameter server-side. Set the
    ``trusted_public_keys`` parameter client-side. Set the other
    parameter on the other side for mutual TLS using raw public keys.

    **Certificate Revocation** siotls doesn't perform any IO on its own,
    this poses a problem when validating certificates, as it must check
    with the CA that the peer's certificate has not been revoked. siotls
    delegates the communication with the CA to the user, via the
    ``crl``, ``ocsp`` and ``cert`` services. The user should choose an
    implementation of those services that integrates with its network
    stack.
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

    static_revocation_list: x509loader.DerCRL | None = None
    """
    To use with :attr:`trust_store`, list the certificate that should be
    considered revoked.
    """

    crl_service: CRLService | None = None
    """
    The service used to download the certificate revocation list (CRL)
    at the autority that issued the peer's certificate. Used to verify
    that the peer's certificate has not been revoked.
    """

    ocsp_service: OCSPService | None = None
    """
    The service used to download the certificate status at the autority
    that issued the peer's certificate. Need :attr:`cert_service`. Used
    to verify that the peer's certificate has not been revoked.
    """

    cert_service: CRTService | None = None
    """
    The service used to download the certificate that signed the OCSP
    response, should that certificate be different than the CA that
    issued the peer's certificate. Need :attr:`ocsp_service`.
    """

    max_chain_depth: int = 5
    """
    Limit the length of the peer's certificate chain when authenticating
    via x509 certificate.
    """

    trusted_public_keys: Sequence[x509loader.DerPublicKey] = ()
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

    private_key: x509loader.DerPrivateKey | None = None
    """
    The private key counter part of :attr:`public_key` and the public
    key found inside the first :attr:`certificate_chain`. Mandatory
    server side, optional client-side (but a server might require for
    mutual TLS).
    """

    public_key: x509loader.DerPublicKey | None = None
    """
    Negotiate :rfc:`7250#` (Raw Public Keys).

    The public key counter part of :attr:`private_key`. Allow this side
    to authenticate using raw public keys.

    When used in addition to :attr:`certificate_chain`, it will send
    either the certificate chain, either the public key, depending on
    the peer's negotiated preference. When used instead of
    :attr:`certificate_chain`, it will either send the public key,
    either fail with an :class:`alerts.UnsupportedCertificate` alert,
    depending on the peer's support for raw public keys.
    """

    certificate_chain: Sequence[x509loader.DerCertificate] | None = None
    """
    The list of certificates that together form a chain of trust between
    the host certificate and a trusted root certificate. Make this side
    authenticate using x509 certificates.

    The first certificate in the list must be the certificate of the
    current host. The following certificates each must sign the previous
    one in the list. The last certificate must be signed by a root CA,
    the root CA itself should not be listed.
    """

    # extensions
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

    Allow this side to reply to echo requests from the peer.

    Note: siotls always negociates sending echo requests to the peer,
    this configuration solely applies to replying to the peer's own
    echo requests.

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

    @functools.cached_property
    def asn1_public_key(self) -> SubjectPublicKeyInfo:
        if self.public_key is None:
            return None
        return x509loader.load_der_public_key(self.public_key)

    @functools.cached_property
    def asn1_private_key(self) -> PrivateKeyInfo:
        if self.public_key is None:
            return None
        return x509loader.load_der_private_key(self.private_key)

    @functools.cached_property
    def asn1_static_revocation_list(self) -> CertificateList:
        if self.static_revocation_list is None:
            return None
        return x509loader.load_der_crl(self.static_revocation_list)

    @functools.cached_property
    def asn1_certificate_chain(self) -> Sequence[Certificate]:
        if self.certificate_chain is None:
            return None
        return x509loader.load_der_certificates(self.certificate_chain)

    @functools.cached_property
    def asn1_trusted_public_keys(self) -> Sequence[SubjectPublicKeyInfo]:
        return [
            x509loader.load_der_public_key(public_key)
            for public_key in self.trusted_public_keys
        ]

    @property
    def require_peer_authentication(self) -> bool:
        return bool(self.trust_store or self.trusted_public_keys)

    @functools.cached_property
    def certificate_types(self) -> Sequence[CertificateType]:
        types = []  # order is important, x509 must be first
        if self.certificate_chain:
            types.append(CertificateType.X509)
        if self.public_key:
            types.append(CertificateType.RAW_PUBLIC_KEY)
        return types

    @functools.cached_property
    def peer_certificate_types(self) -> Sequence[CertificateType]:
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
    def other_side(self) -> typing.Literal['client', 'server']:
        """ The side of the peer. """
        return 'server' if self.side == 'client' else 'client'

    def __post_init__(self):
        self._check_mandatory_settings()
        if self.side == 'server':
            self._check_server_settings()
        else:
            self._check_client_settings()

        self._load_asn1_objects()
        if self.certificate_chain:
            self._check_certificate_chain()
        if self.public_key:
            self._check_public_key()

        if (self.require_peer_authentication
            and self.static_revocation_list is None
            and self.ocsp_service is None
            and self.crl_service is None
        ):
            w =("missing static revocation list, ocsp service, or crl "
                "service: online certificate revocation check disabled")
            logger.warning(w)

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
                "will not verify the peer's certificate")
            logger.warning(w)
        if self.server_hostnames:
            e =("the configuration's (plural) server_hostnames is "
                "meant for the server side, maybe you intended to use "
                "the connection's (singular) server_hostname instead")
            raise ValueError(e)

    def _check_certificate_chain(self):
        if not self.private_key:
            e = "certificate chain provided but private key missing"
            raise ValueError(e)

        pubkey_info = self.asn1_certificate_chain[0]['tbsCertificate']['subjectPublicKeyInfo']
        # TODO: verify that the public key found inside the certificate
        #       corresponds to the private key.

        suites = TLSSignatureScheme.for_key_algo(pubkey_info['algorithm'])
        suites_iana_id = {suite.iana_id for suite in suites}
        if suites_iana_id.isdisjoint(self.signature_algorithms):
            e =("the public key extracted from the certificate can "
                "be used with the following signature algorithms: "
                f"{sorted(suites_iana_id)} but none of them is found "
                "in the configured signature algorithms: "
                f"{sorted(self.signature_algorithms)}")
            raise ValueError(e)

    def _check_public_key(self):
        if not self.private_key:
            e = "public key provided but private key missing"
            raise ValueError(e)
        # TODO: verify that the public key corresponds to the private key.

        suites = TLSSignatureScheme.for_key_algo(self.asn1_public_key['algorithm'])
        suites_iana_id = {suite.iana_id for suite in suites}
        if suites_iana_id.isdisjoint(self.signature_algorithms):
            e =("the public key can be used with the following "
                f"signature algorithms: {sorted(suites_iana_id)} but "
                "none of them is found in the configured signature "
                f"algorithms: {sorted(self.signature_algorithms)}")
            raise ValueError(e)

    def _load_asn1_objects(self):
        # ruff: noqa: B018
        self.asn1_certificate_chain
        self.asn1_private_key
        self.asn1_public_key
        self.asn1_trusted_public_keys


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
    peer_certificate: x509loader.DerCertificate | None
    peer_public_key: x509loader.DerPublicKey | None

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

    @functools.cached_property
    def asn1_peer_certificate(self):
        if self.peer_certificate is None:
            return None
        return x509loader.load_der_certificate(self.peer_certificate)

    @functools.cached_property
    def asn1_peer_public_key(self):
        if self.peer_public_key is None:
            return None
        return x509loader.load_der_public_key(self.peer_public_key)

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

    def copy(self):
        copy = type(self)()
        copy.cipher_suite = self.cipher_suite
        copy.key_exchange = self.key_exchange
        copy.signature_algorithm = self.signature_algorithm
        copy.alpn = self.alpn
        copy.can_send_heartbeat = self.can_send_heartbeat
        copy.can_echo_heartbeat = self.can_echo_heartbeat
        copy.max_fragment_length = self.max_fragment_length
        copy.client_certificate_type = self.client_certificate_type
        copy.server_certificate_type = self.server_certificate_type
        copy.peer_want_ocsp_stapling = self.peer_want_ocsp_stapling
        copy.peer_certificate = self.peer_certificate
        copy.peer_public_key = self.peer_public_key
        return copy
