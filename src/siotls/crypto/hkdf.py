""" RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function (HKDF) """

import hmac
import math


def hkdf_extract(digestmod, salt, input_keying_material):
    if not salt:
        salt = b'\x00' * digestmod().digest_size
    pseudorandom_key = hmac.digest(salt, input_keying_material, digestmod)
    return pseudorandom_key

def hkdf_expand(digestmod, pseudorandom_key, info, okm_length):
    if okm_length == digestmod().digest_size:
        return hmac.digest(pseudorandom_key, info + b'\x01', digestmod)

    n = math.ceil(okm_length / digestmod().digest_size)

    t = [b'']
    for i in range(1, n + 1):
        msg = b''.join((t[i - 1], info, i.to_bytes(1, 'big')))
        t.append(hmac.digest(pseudorandom_key, msg, digestmod))

    output_keying_material = b''.join(t)[:okm_length]
    return output_keying_material

def hkdf_expand_label(digestmod, secret, label, context, length):
    label = b'tls13 ' + label
    hkdf_label = b''.join([
        length.to_bytes(2, 'big'),
        len(label).to_bytes(1, 'big'),
        label,
        len(context).to_bytes(1, 'big'),
        context,
    ])
    return hkdf_expand(digestmod, secret, hkdf_label, length)

def derive_secret(digestmod, secret, label, transcript_hash):
    return hkdf_expand_label(
        digestmod, secret, label, transcript_hash, digestmod().digest_size)
