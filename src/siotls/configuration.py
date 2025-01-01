import dataclasses
import functools
import logging
import typing

from cryptography.x509.verification import PolicyBuilder, Store

import siotls.x509.loader as x509loader
from siotls.crypto import TLSSignatureSuite
from siotls.iana import (
    ALPNProtocol,
    CertificateType,
    CipherSuites,
    MaxFragmentLengthOctets as MLFOctets,
    NamedGroup,
    SignatureScheme,
)
from siotls.services import CRLService, OCSPService

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
    static_revocation_list: x509loader.DerCRL | None = None
    ocsp_service: OCSPService | None = None
    crl_service: CRLService | None = None
    max_chain_depth: int = 5
    trusted_public_keys: list[x509loader.DerPublicKey] = dataclasses.field(default_factory=list)

    private_key: x509loader.DerPrivateKey | None = None
    public_key: x509loader.DerPublicKey | None = None
    certificate_chain: list[x509loader.DerCertificate] | None = None

    # extensions
    max_fragment_length: MLFOctets = MLFOctets.MAX_16384
    can_echo_heartbeat: bool = True
    alpn: list[ALPNProtocol] = dataclasses.field(default_factory=list)
    server_hostnames: list[str] = dataclasses.field(default_factory=list)

    # extra
    log_keys: bool = False

    @functools.cached_property
    def asn1_public_key(self):
        if self.public_key is None:
            return None
        return x509loader.load_der_public_key(self.public_key)

    @functools.cached_property
    def asn1_private_key(self):
        if self.public_key is None:
            return None
        return x509loader.load_der_private_key(self.private_key)

    @functools.cached_property
    def asn1_static_revocation_list(self):
        if self.static_revocation_list is None:
            return None
        return x509loader.load_der_crl(self.static_revocation_list)

    @functools.cached_property
    def asn1_certificate_chain(self):
        return x509loader.load_der_certificates(self.certificate_chain)

    @functools.cached_property
    def asn1_trusted_public_keys(self):
        return [
            x509loader.load_der_public_key(public_key)
            for public_key in self.trusted_public_keys
        ]

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
        if self.private_key.public_key() != self.certificate_chain[0].public_key():
            e =("the public key extracted from the certificate "
                "doesn't match the private key")
            raise ValueError(e)

        suites = {
            suite.iana_id: suite for suite in
            TLSSignatureSuite.for_certificate(self.certificate_chain[0])
        }
        if set(suites).isdisjoint(self.signature_algorithms):
            e =("the public key extracted from the certificate can "
                "be used with the following signature algorithms: "
                f"{sorted(suites)} but none of them is found in "
                "the configured signature algorithms: "
                f"{sorted(self.signature_algorithms)}")

    def _check_public_key(self):
        if not self.private_key:
            e = "public key provided but private key missing"
            raise ValueError(e)
        if self.private_key.public_key() != self.public_key:
            e = "the public key doesn't match the private key"
            raise ValueError(e)

        suites = TLSSignatureSuite.for_key(self.public_key)
        if set(suites).isdisjoint(self.signature_algorithms):
            e =("the public key can be used with the following "
                f"signature algorithms: {sorted(suites)} but none "
                "of them is found in the configured signature "
                f"algorithms: {sorted(self.signature_algorithms)}")

    def _load_asn1_objects(self):
        # ruff: noqa: B018
        self.asn1_certificate_chain
        self.asn1_private_key
        self.asn1_public_key
        self.asn1_trusted_public_keys


@dataclasses.dataclass(init=False)
class TLSNegotiatedConfiguration:
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
