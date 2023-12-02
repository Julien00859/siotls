"""
The Transcript Hash is a running sha2 of the handshake messages echanged
in the original handshakes. The digest is used many times, at various
stages of the exchange, by the TLSSecrets class. The digest, together
with the key exchanged via KeyShare or PreSharedKey, is used to generate
the many secrets key used by the AEAD algorithms to encrypt exchanges.

There are shenanigans regarding ClientHello and HelloRetryRequest that
make the implementation unfortunately not trivial.

ClientHello
-----------

The client can offer multiple cipher suites in its first ClientHello,
different offered cipher suites can come with different hashing
algorithm, e.g. TLS_AES_128_GCM_SHA256 vs TLS_AES_256_GCM_SHA384 (SHA256
vs SHA386). The actual hashing algorithm to use for this connection will
only be known with the ServerHello/HelloRetryRequest hanshake of the
server.

This means that either (1) we have to keep the ClientHello message
around until we know what hash algorithm the server decides to use and
only then compute the transcript hash, either (2) we save multiple
hashes and then discard those we won't use. The current implementation
uses (2) as several passages of the TLS RFC hint at this choice and that
it seems to be the common method used by many TLS implementations.

In cases multiple differents hashing algorithms are offered, that until
receiving ServerHello/HelloRetryRequest we do not know which one will be
used, it is forbidden to request a digest (via the digest() and
hexdigest() methods) before calling post_init().

This has an important implication regarding TLSSecret and Early Data:
the transcript hash of ClientHello is used when generating the "early
exported master" and "client early traffic" secrets. Those secrets are
generated and used before receiving ServerHello/HelloRetryRequest. All
the pre-shared-keys all must share the same hashing algorithm othersise
it would be impossible to generate the secrets.

HelloRetryRequest
-----------------

TLS 1.3 claims that it is possible to do a stateless HelloRetryRequest
using a clever (but not smart) hack. We still don't know how to do a
stateless HelloRetryRequest but we still have to implement the hack
otherwise the transcript wouldn't be right.


"""

from siotls.iana import HandshakeType, HandshakeType_
from siotls.contents import alerts


ORDER = [
    ('client', HandshakeType.CLIENT_HELLO),
    ('server', HandshakeType_.HELLO_RETRY_REQUEST),
    ('client', HandshakeType.CLIENT_HELLO),
    ('server', HandshakeType.SERVER_HELLO),
    ('server', HandshakeType.ENCRYPTED_EXTENSIONS),
    ('server', HandshakeType.CERTIFICATE_REQUEST),
    ('server', HandshakeType.CERTIFICATE),
    ('server', HandshakeType.CERTIFICATE_VERIFY),
    ('server', HandshakeType.FINISHED),
    ('client', HandshakeType.END_OF_EARLY_DATA),
    ('client', HandshakeType.CERTIFICATE),
    ('client', HandshakeType.CERTIFICATE_VERIFY),
    ('client', HandshakeType.FINISHED),
    None
]


class Transcript:
    def __init__(self, digestmods):
        if not digestmods:
            e = "empty digestmods"
            raise ValueError(e)
        if len(digestmods) == 1:
            self._hash = next(iter(digestmods))()
        else:
            self._hash = None
            self._hashes = [dm() for dm in digestmods]
        self._order_i = 2  # expect ClientHello

    def post_init(self, digestmod):
        assert self._order_i == 3
        if digestmod == type(self._hash):
            return
        for hash_ in self._hashes:
            if type(hash_) is digestmod:
                self._hash = hash_
                return
        e = f"{digestmod} not found inside {self._hashes}"
        raise ValueError(e)

    def do_hrr_dance(self):
        assert self._hash and self._order_i == 3
        self._hash = type(self._hash)(b''.join([
            HandshakeType.MESSAGE_HASH.to_bytes(1, 'big'),
            b'\x00\x00',
            self.digest(),
        ]))
        self._order_i = 1  # expect HelloRetryRequest

    def update(self, side, handshake_type, handshake_data):
        if self._order_i == ORDER:
            return
        if (side, handshake_type) != ORDER[self._order_i]:
            e =(f"Was expecting {ORDER[self._order_i]} but found "
                f"{(side, handshake_type)} instead.")
            raise alerts.UnexpectedMessage(e)
        if self._hash:
            self._hash.update(handshake_data)
        else:
            self._sha256.update(handshake_data)
            self._sha384.update(handshake_data)

    def digest(self):
        return self._hash.digest()

    def hexdigest(self):
        return self._hash.hexdigest()
