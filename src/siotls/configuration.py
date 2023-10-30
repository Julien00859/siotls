import dataclasses
import typing
from siotls.iana import (
    CipherSuites,
    SignatureScheme,
    NamedGroup,
    ALPNProtocol,
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
    max_fragment_length: typing.Literal[
        512, 1024, 2048, 4096, 16384,
    ] = 16384
    can_send_heartbeat: bool = False
    can_echo_heartbeat: bool = True
    alpn: list[ALPNProtocol] = dataclasses.field(default_factory=list)
    hostnames: list[str] = dataclasses.field(default_factory=list)

    def validate(self):
        if self.side == 'server' and self.max_fragment_length != 16384:
            e = "max fragment length is only configurable client side"
            raise ValueError(e)


@dataclasses.dataclass(frozen=True)
class TLSNegociatedConfiguration:
    cipher_suite: CipherSuites
    digital_signature: SignatureScheme
    key_exchange: NamedGroup
    alpn: ALPNProtocol | None
    can_send_heartbeat: bool
    can_echo_heartbeat: bool
    max_fragment_length: int
