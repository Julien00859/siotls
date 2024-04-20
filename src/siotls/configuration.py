import dataclasses
import logging
import typing

from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
)
from cryptography.x509 import Certificate
from cryptography.x509.verification import Store

from siotls.crypto.signatures import TLSSignatureSuite
from siotls.iana import (
    ALPNProtocol,
    CipherSuites,
    MaxFragmentLengthOctets as MLFOctets,
    NamedGroup,
    SignatureScheme,
)

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class TLSConfiguration:
    side: typing.Literal['client', 'server']
    _: dataclasses.KW_ONLY

    # mandatory
    cipher_suites: list[CipherSuites] = \
        dataclasses.field(default_factory=[
            CipherSuites.TLS_CHACHA20_POLY1305_SHA256,
            CipherSuites.TLS_AES_256_GCM_SHA384,
            CipherSuites.TLS_AES_128_GCM_SHA256,
        ].copy)
    key_exchanges: list[NamedGroup] = \
        dataclasses.field(default_factory=[
            NamedGroup.x25519,
            NamedGroup.secp256r1,
        ].copy)
    signature_algorithms: list[NamedGroup] = \
        dataclasses.field(default_factory=[
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
        ].copy)

    trust_store: Store | None = None

    private_key: PrivateKeyTypes | None = None
    certificate_chain: list[Certificate] | None = None

    # extensions
    max_fragment_length: MLFOctets = MLFOctets.MAX_16384
    can_echo_heartbeat: bool = True
    alpn: list[ALPNProtocol] = dataclasses.field(default_factory=list)
    hostnames: list[str] = dataclasses.field(default_factory=list)

    # extra
    log_keys: bool = False

    @property
    def require_peer_certificate(self):
        return bool(self.trust_store)

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
        if not self.certificate_chain:
            e = "a certificate is mandatory server side"
            raise ValueError(e)
        if self.require_peer_certificate:
            m =("a trust store is provided, client certificates will "
                "be requested")
            logger.info(m)

    def _check_client_settings(self):
        if not self.trust_store:
            w =("no trust store provided, server certificate "
                "validation disabled")
            logger.warning(w)


@dataclasses.dataclass(init=False)
class TLSNegociatedConfiguration:
    cipher_suite: CipherSuites
    key_exchange: NamedGroup | None
    signature_algorithm: SignatureScheme | None
    alpn: ALPNProtocol | None | type(...)
    can_send_heartbeat: bool | None
    can_echo_heartbeat: bool | None
    max_fragment_length: MLFOctets | None

    def __init__(self, cipher_suite):
        object.__setattr__(self, '_frozen', False)
        self.cipher_suite = cipher_suite
        self.key_exchange = None
        self.signature_algorithm = None
        self.alpn = ...  # None is part of the domain, using Ellipsis as "not set" value
        self.can_send_heartbeat = None
        self.can_echo_heartbeat = None
        self.max_fragment_length = None

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
