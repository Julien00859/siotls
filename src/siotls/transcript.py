"""
The Transcript Hash is a running sha2 of the handshake messages exchanged
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

import hashlib

from siotls.contents import alerts
from siotls.iana import HandshakeType, HandshakeType_

ORDER = [
    ('client', HandshakeType.MESSAGE_HASH, False),
    ('server', HandshakeType_.HELLO_RETRY_REQUEST, False),
    ('client', HandshakeType.CLIENT_HELLO, False),
    ('server', HandshakeType.SERVER_HELLO, False),
    ('server', HandshakeType.ENCRYPTED_EXTENSIONS, False),
    ('server', HandshakeType.CERTIFICATE_REQUEST, True),  # skippable
    ('server', HandshakeType.CERTIFICATE, False),
    ('server', HandshakeType.CERTIFICATE_VERIFY, False),
    ('server', HandshakeType.FINISHED, False),
    ('client', HandshakeType.END_OF_EARLY_DATA, True),    # skippable
    ('client', HandshakeType.CERTIFICATE, True),          # skippable
    ('client', HandshakeType.CERTIFICATE_VERIFY, True),   # skippable
    ('client', HandshakeType.FINISHED, False),
]


class Transcript:
    def __init__(self, digestmods):
        if not digestmods:
            e = "empty digestmods"
            raise ValueError(e)
        self._digestmod = None
        self._digestmods = [dm() for dm in digestmods]
        self._order_i = 2
        self._client_hello_transcripts = {}

    def post_init(self, digestmod):
        name = digestmod().name
        self._digestmod = next((h for h in self._digestmods if h.name == name), None)
        if not self._digestmod:
            e = f"{digestmod} not found inside {self._digestmods}"
            raise ValueError(e)
        self._digestmods.clear()

    def do_hrr_dance(self):
        """
        Transcript-Hash(ClientHello1, HelloRetryRequest, ... Mn) =
            Hash(message_hash ||        /* Handshake type */
                 00 00 Hash.length  ||   /* Handshake message length (bytes) */
                 Hash(ClientHello1) ||  /* Hash of ClientHello1 */
                 HelloRetryRequest  || ... || Mn)
        """
        self._order_i = 0
        self._digestmod = hashlib.new(self._digestmod.name, b'')

        message_hash = b''.join((
            HandshakeType.MESSAGE_HASH.to_bytes(1, 'big'),
            b'\x00\x00',
            self._digestmod.digest_size.to_bytes(1, 'big'),
            self._client_hello_transcripts[self._digestmod.name],
        ))
        self.update(message_hash, 'client', HandshakeType.MESSAGE_HASH)

    def update(self, handshake_data, side, handshake_type):
        # the transcript should only be updated during the initial handshake
        if self._order_i == len(ORDER):
            return

        # extra safety net, the states should validate the incomming
        # messages and by construction always send valid handshakes
        expected_side, expected_handshake, is_skippable = ORDER[self._order_i]
        while is_skippable and (side, handshake_type) != (expected_side, expected_handshake):
            self._order_i += 1
            expected_side, expected_handshake, is_skippable = ORDER[self._order_i]
        if (side, handshake_type) != (expected_side, expected_handshake):
            e =(f"was expecting {(expected_side, expected_handshake)} "
                f"but found {(side, handshake_type)} instead")
            raise alerts.UnexpectedMessage(e)

        # update the transcript
        if self._digestmod:
            self._digestmod.update(handshake_data)
        for dm in self._digestmods:
            dm.update(handshake_data)

        # save the transcript after the first client hello, for the
        # hello retry request (hrr) dance
        if handshake_type == HandshakeType.CLIENT_HELLO:
            for dm in self._digestmods:
                self._client_hello_transcripts[dm.name] = dm.digest()
        elif handshake_type == HandshakeType.ENCRYPTED_EXTENSIONS:
            self._client_hello_transcripts.clear()

        self._order_i += 1

    def digest(self):
        return self._digestmod.digest()

    def hexdigest(self):
        return self._digestmod.hexdigest()

    def copy(self):
        dummy = bool
        copy = type(self)([dummy])
        if self._digestmods:
            copy._digestmods = [  # noqa: SLF001
                h.copy() for h in self._digestmods
            ]
            copy._digestmod = None  # noqa: SLF001
        else:
            copy._digestmod = []  # noqa: SLF001
            copy._digestmod = self._digestmod.copy()  # noqa: SLF001
        copy._order_i = self._order_i  # noqa: SLF001
        return copy
