import dataclasses
import typing
from siotls.ciphers import cipher_map, digest_map
from siotls.iana import (
    CipherSuites,
    SignatureScheme,
    NamedGroup,
    ALPNProtocol,
    MaxFragmentLengthOctets as MLFOctets,
)


@dataclasses.dataclass()
class TLSConfiguration:
    side: typing.Literal['client', 'server']

    # mandatory
    cipher_suites: list[CipherSuites] = \
        dataclasses.field(default_factory=[
            CipherSuites.TLS_CHACHA20_POLY1305_SHA256,
            CipherSuites.TLS_AES_256_GCM_SHA384,
            CipherSuites.TLS_AES_128_GCM_SHA256,
        ].copy)
    digital_signatures: list[SignatureScheme] = \
        dataclasses.field(default_factory=[
            SignatureScheme.rsa_pkcs1_sha256,
            SignatureScheme.rsa_pss_rsae_sha256,
            SignatureScheme.ecdsa_secp256r1_sha256,
        ].copy)
    key_exchanges: list[NamedGroup] = \
        dataclasses.field(default_factory=[
            NamedGroup.x25519,
            NamedGroup.secp256r1,
        ].copy)

    # extensions
    max_fragment_length: MLFOctets = MLFOctets.MAX_16384
    can_send_heartbeat: bool = False
    can_echo_heartbeat: bool = True
    alpn: list[ALPNProtocol] = dataclasses.field(default_factory=list)
    hostnames: list[str] = dataclasses.field(default_factory=list)

    # extra
    log_keys: bool = False

    @property
    def other_side(self):
        return 'server' if self.side == 'client' else 'client'

    def validate(self):
        if self.side == 'server':
            if self.max_fragment_length != MLFOctets.MAX_16384:
                e = "max fragment length is only configurable client side"
                raise ValueError(e)


@dataclasses.dataclass(init=False)
class TLSNegociatedConfiguration:
    # Using ellipsis is an implementation detail and should not be taken
    # into account by users. The negociation spans multiple messages, we
    # cannot build the entire object at once and ellipsis is the least
    # annoying solution we found to still use what have been negociated.
    cipher_suite: CipherSuites
    ciphermod: typing.Any  # cryptography.hazmat.primitives.ciphers.aead
    digestmod: typing.Any  # hashlib
    digital_signature: SignatureScheme | Ellipsis
    key_exchange: NamedGroup | Ellipsis
    alpn: ALPNProtocol | None
    can_send_heartbeat: bool | Ellipsis
    can_echo_heartbeat: bool | Ellipsis
    max_fragment_length: MLFOctets | Ellipsis

    def __init__(self, cipher_suite):
        self.cipher_suite = cipher_suite
        self.ciphermod = cipher_map[cipher_suite]
        self.digestmod = digest_map[cipher_suite]
        self.digital_signature = ...
        self.key_exchange = ...
        self.alpn = ...
        self.can_send_heartbeat = ...
        self.can_echo_heartbeat = ...
        self.max_fragment_length = ...
