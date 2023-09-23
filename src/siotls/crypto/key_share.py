from cryptography.hazmat.primitives.asymmetric import dh
from siotls.contents import alerts
from . import ffdhe

def init(key_exchange):
    if key_exchange.is_sec():
        return init_sec(key_exchange)
    elif key_exchange.is_x():
        return init_x(key_exchange)
    else:  # key_exchange.is_ff()
        return init_ff(key_exchange)

def resume(key_exchange, peer_key_share):
    if key_exchange.is_sec():
        return resume_sec(key_exchange, peer_key_share)
    elif key_exchange.is_x():
        return resume_x(key_exchange, peer_key_share)
    else:  # key_exchange.is_ff()
        return resume_ff(key_exchange, peer_key_share)


def init_sec(key_exchange):
    raise NotImplementedError("todo")

def resume_sec(key_exchange, peer_key_share):
    raise NotImplementedError("todo")


def init_x(key_exchange):
    raise NotImplementedError("todo")

def resume_x(key_exchange, peer_key_share):
    raise NotImplementedError("todo")


def init_ff(key_exchange):
    p, g, q, p_length, min_key_length = ffdhe.groups[key_exchange]
    params = dh.DHParameterNumbers(p, q).parameters()
    private_key = params.generate_private_key()

    y = private_key.public_key().public_numbers().y
    my_key_share = y.to_bytes(p_length, 'big')

    return private_key, my_key_share

def resume_ff(key_exchange, peer_key_share):
    p, g, q, p_length, min_key_length = ffdhe.groups[key_exchange]
    if len(peer_key_share) < min_key_length:
        raise alerts.InsufficientSecurity()

    pn = dh.DHParameterNumbers(p, q)
    x = int.from_bytes(peer_key_share, 'big')
    pubkey = dh.DHPublicNumbers(x, pn).public_key()

    privkey = pn.parameters().generate_private_key()
    y = privkey.public_key().public_numbers().y
    my_key_share = y.to_bytes(p_length, 'big')

    shared_key = privkey.exchange(pubkey)
    return shared_key, my_key_share
