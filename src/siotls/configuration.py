import dataclasses
import functools
import logging
import typing

from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)
from cryptography.x509 import Certificate
from cryptography.x509.verification import Store

from siotls.crypto.trust_store import build_system_store
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

    trust_store: Store | None = None
    trusted_public_keys: list[PublicKeyTypes] = dataclasses.field(default_factory=list)

    private_key: PrivateKeyTypes | None = None
    public_key: PublicKeyTypes | None = None
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
        return bool(self.trust_store or self.trusted_public_keys)

    @functools.cached_property
    def certificate_types(self):
        types = []
        if self.certificate_chain:
            types.append(CertificateType.X509)
        if self.public_key:
            types.append(CertificateType.RawPublicKey)
        return types

    @functools.cached_property
    def peer_certificate_types(self):
        types = []
        if self.trust_store:
            types.append(CertificateType.X509)
        if self.trusted_public_keys:
            types.append(CertificateType.RawPublicKey)
        return types

    @property
    def other_side(self):
        return 'server' if self.side == 'client' else 'client'

    def __post_init__(self):
        if self.side == 'server':
            if self.max_fragment_length != MLFOctets.MAX_16384:
                e = "max fragment length is only configurable client side"
                raise ValueError(e)

            if not self.private_key:
                e = "the private key is mandatory server side"
                raise ValueError(e)

            if not self.certificate_chain:
                e = "the certificate chain is mandatory server side"
                raise ValueError(e)


@dataclasses.dataclass(init=False)
class TLSNegociatedConfiguration:
    cipher_suite: CipherSuites
    signature_algorithm: SignatureScheme | None
    key_exchange: NamedGroup | None
    alpn: ALPNProtocol | None | type(...)
    can_send_heartbeat: bool | None
    can_echo_heartbeat: bool | None
    max_fragment_length: MLFOctets | None
    client_certificate_type: CertificateType | None
    server_certificate_type: CertificateType | None
    peer_public_key: PublicKeyTypes | None = None
    peer_certificate_chain: list[Certificate] | None = None

    def __init__(self, cipher_suite):
        object.__setattr__(self, '_frozen', False)
        self.cipher_suite = cipher_suite
        self.signature_algorithm = None
        self.key_exchange = None
        self.alpn = ...  # None is part of the domain, using Ellipsis as "not set" value
        self.can_send_heartbeat = None
        self.can_echo_heartbeat = None
        self.max_fragment_length = None
        self.client_certificate_type = None
        self.server_certificate_type = None
        self.peer_public_key = None
        self.peer_certificate_chain = None

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
