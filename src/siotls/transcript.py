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

from siotls.iana import HandshakeType
from siotls.contents import alerts


ORDER = [
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
]


class Transcript:
    def __init__(self, digestmods):
        if not digestmods:
            e = "empty digestmods"
            raise ValueError(e)
        self._hashes = [dm() for dm in digestmods]
        self._order_i = 0

    def post_init(self, digestmod):
        name = digestmod().name
        hash_ = next((h for h in self._hashes if h.name == name), None)
        if not hash_:
            e = f"{digestmod} not found inside {self._hashes}"
            raise ValueError(e)
        self._hashes.clear()
        self._hashes.append(hash_)

    def do_hrr_dance(self):
        assert self._order_i == 2, \
            "can only dance after receiving/sending HelloRetryRequest"
        self._hashes[0] = type(self._hashes[0])(b''.join([
            HandshakeType.MESSAGE_HASH.to_bytes(1, 'big'),
            b'\x00\x00',
            self.digest(),
        ]))
        self._order_i = 0  # expect ClientHello

    def update(self, handshake_data, side, handshake_type):
        if self._order_i == len(ORDER):
            return
        if (side, handshake_type) != ORDER[self._order_i]:
            e =(f"Was expecting {ORDER[self._order_i]} but found "
                f"{(side, handshake_type)} instead.")
            raise alerts.UnexpectedMessage(e)
        for hash_ in self._hashes:
            hash_.update(handshake_data)
        self._order_i += 1

    def digest(self):
        return self._hashes[0].digest()

    def hexdigest(self):
        return self._hashes[0].hexdigest()

    def clone(self):
        return self._hashes[0].close()
