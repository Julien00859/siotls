from cryptography.hazmat.primitives.asymmetric import dh, ec, x448, x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import siotls
from siotls.crypto.key_exchanges import (
    Ffdhe2048Mixin,
    Ffdhe3072Mixin,
    Ffdhe4096Mixin,
    Ffdhe6144Mixin,
    Ffdhe8192Mixin,
    Secp256R1Mixin,
    Secp384R1Mixin,
    Secp521R1Mixin,
    TLSKeyExchange,
    X448Mixin,
    X25519Mixin,
)


class _XMixin:
    @classmethod
    def init(cls):
        private_key = cls.PrivateKey.generate()
        my_key_share = private_key.public_key().public_bytes_raw()
        return private_key, my_key_share

    @classmethod
    def resume(cls, private_key, peer_key_share):
        peer_public_key = cls.PublicKey.from_public_bytes(peer_key_share)
        shared_key = private_key.exchange(peer_public_key)
        return shared_key

class X25519(X25519Mixin, _XMixin, TLSKeyExchange):
    PrivateKey = x25519.X25519PrivateKey
    PublicKey = x25519.X25519PublicKey

class X448(X448Mixin, _XMixin, TLSKeyExchange):
    PrivateKey = x448.X448PrivateKey
    PublicKey = x448.X448PublicKey


class _SecpMixin:
    @classmethod
    def init(cls):
        private_key = ec.generate_private_key(cls.curve())
        my_key_share = private_key.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )
        return private_key, my_key_share

    @classmethod
    def resume(cls, private_key, peer_key_share):
        peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            cls.curve(), peer_key_share
        )
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        return shared_key

class Secp256R1(Secp256R1Mixin, _SecpMixin, TLSKeyExchange):
    curve = ec.SECP256R1

class Secp384R1(Secp384R1Mixin, _SecpMixin, TLSKeyExchange):
    curve = ec.SECP384R1

class Secp521R1(Secp521R1Mixin, _SecpMixin, TLSKeyExchange):
    curve = ec.SECP521R1


class _FfdheMixin:
    @classmethod
    def init(cls):
        params = dh.DHParameterNumbers(cls.p, cls.g, cls.q).parameters()
        private_key = params.generate_private_key()

        y = private_key.public_key().public_numbers().y
        my_key_share = y.to_bytes(cls.p_length, 'big')

        return private_key, my_key_share

    @classmethod
    def resume(cls, private_key, peer_key_share):
        if len(peer_key_share.lstrip(b'\x00')) < cls.min_key_length:
            e = "the peer's key is too short"
            raise siotls.contents.alerts.InsufficientSecurity(e)

        y = int.from_bytes(peer_key_share, 'big')
        if not (1 < y < cls.p - 1):
            e = "invalid peer ffdhe Y"
            raise ValueError(e)

        pn = dh.DHParameterNumbers(cls.p, cls.g, cls.q)
        pubkey = dh.DHPublicNumbers(y, pn).public_key()
        shared_key = private_key.exchange(pubkey)
        return shared_key

class Ffdhe2048(Ffdhe2048Mixin, _FfdheMixin, TLSKeyExchange):
    pass

class Ffdhe3072(Ffdhe3072Mixin, _FfdheMixin, TLSKeyExchange):
    pass

class Ffdhe4096(Ffdhe4096Mixin, _FfdheMixin, TLSKeyExchange):
    pass

class Ffdhe6144(Ffdhe6144Mixin, _FfdheMixin, TLSKeyExchange):
    pass

class Ffdhe8192(Ffdhe8192Mixin, _FfdheMixin, TLSKeyExchange):
    pass
