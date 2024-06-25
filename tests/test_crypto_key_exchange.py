import unittest

from parameterized import parameterized

from siotls.crypto import TLSKeyExchange
from siotls.iana import NamedGroup

try:
    from sympy import isprime
except ImportError:
    isprime = None

from . import TAG_SLOW


class TestCryptoKeyShare(unittest.TestCase):
    @parameterized.expand([(group.name, group.value) for group in NamedGroup])
    @unittest.skipUnless(TAG_SLOW, "enable with SIOTLS_SLOW=1")
    def test_crypto_key_share_cycle(self, _, key_exchange):
        KeyExchange = TLSKeyExchange[key_exchange]  # noqa: N806
        client_priv, client_pub = KeyExchange.init()
        server_priv, server_pub = KeyExchange.init()
        server_shared = KeyExchange.resume(server_priv, client_pub)
        client_shared = KeyExchange.resume(client_priv, server_pub)
        self.assertEqual(server_shared, client_shared)

    @parameterized.expand([
        (group.name, group.value)
        for group in NamedGroup
        if 'ffdhe' in group.name
    ])
    @unittest.skipUnless(isprime, "sympy not found in sys.modules")
    @unittest.skipUnless(TAG_SLOW, "enable with SIOTLS_SLOW=1")
    def test_crypto_key_share_ffdhe_coprimes(self, _, ffdhe_group):
        FFDHE = TLSKeyExchange[ffdhe_group]  # noqa: N806
        self.assertTrue(FFDHE.q == FFDHE.p // 2, "q must equal 2*p+1")
        self.assertTrue(isprime(FFDHE.p), "p must be a prime number")
        self.assertTrue(isprime(FFDHE.q), "p must be a prime number")
