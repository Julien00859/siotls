from cryptography.hazmat.primitives.asymmetric import dh, x448, x25519

from siotls.contents import alerts
from siotls.iana import NamedGroup

from . import ffdhe


def init(key_exchange):
    match key_exchange:
        case NamedGroup.x25519:
            return init_x25519()
        case NamedGroup.x448:
            return init_x448()
        case _ if key_exchange.is_sec():
            raise NotImplementedError("todo")  # noqa: EM101
        case _ if key_exchange.is_ff():
            return init_ff(key_exchange)

def resume(key_exchange, private_key, peer_key_share):
    match key_exchange:
        case NamedGroup.x25519:
            return resume_x25519(private_key, peer_key_share)
        case NamedGroup.x448:
            return resume_x448(private_key, peer_key_share)
        case _ if key_exchange.is_sec():
            raise NotImplementedError("todo")  # noqa: EM101
        case _ if key_exchange.is_ff():
            return resume_ff(key_exchange, private_key, peer_key_share)


def init_x25519():
    private_key = x25519.X25519PrivateKey.generate()
    my_key_share = private_key.public_key().public_bytes_raw()
    return private_key, my_key_share

def resume_x25519(private_key, peer_key_share):
    private_key = private_key or x25519.X25519PrivateKey.generate()
    my_key_share = private_key.public_key().public_bytes_raw()
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_key_share)
    shared_key = private_key.exchange(peer_public_key)
    return shared_key, my_key_share

def init_x448():
    private_key = x448.X448PrivateKey.generate()
    my_key_share = private_key.public_key().public_bytes_raw()
    return private_key, my_key_share

def resume_x448(private_key, peer_key_share):
    private_key = private_key or x448.X448PrivateKey.generate()
    my_key_share = private_key.public_key().public_bytes_raw()
    peer_public_key = x448.X448PublicKey.from_public_bytes(peer_key_share)
    shared_key = private_key.exchange(peer_public_key)
    return shared_key, my_key_share


def init_ff(key_exchange):
    p, g, q, p_length, min_key_length = ffdhe.groups[key_exchange]
    params = dh.DHParameterNumbers(p, q).parameters()
    private_key = params.generate_private_key()

    y = private_key.public_key().public_numbers().y
    my_key_share = y.to_bytes(p_length, 'big')

    return private_key, my_key_share

def resume_ff(key_exchange, private_key, peer_key_share):
    p, g, q, p_length, min_key_length = ffdhe.groups[key_exchange]
    if len(peer_key_share) < min_key_length:
        e = "The peer's key doesn't meet our security requirements"
        raise alerts.InsufficientSecurity(e)

    pn = dh.DHParameterNumbers(p, q)
    x = int.from_bytes(peer_key_share, 'big')
    pubkey = dh.DHPublicNumbers(x, pn).public_key()

    private_key = private_key or pn.parameters().generate_private_key()
    y = private_key.public_key().public_numbers().y
    my_key_share = y.to_bytes(p_length, 'big')

    shared_key = private_key.exchange(pubkey)
    return shared_key, my_key_share
