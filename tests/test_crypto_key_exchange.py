import unittest

from siotls.crypto import TLSKeyExchange
from siotls.iana import NamedGroup

try:
    from sympy import isprime
except ImportError:
    isprime = None


class TestCryptoKeyShare(unittest.TestCase):
    def test_crypto_key_share_matrix(self):
        for key_exchange in NamedGroup:
            with self.subTest(key_exchange=key_exchange):
                KeyExchange = TLSKeyExchange[key_exchange]  # noqa: N806
                client_priv, client_pub = KeyExchange.init()
                server_priv, server_pub = KeyExchange.init()
                server_shared = KeyExchange.resume(server_priv, client_pub)
                client_shared = KeyExchange.resume(client_priv, server_pub)
                self.assertEqual(server_shared, client_shared)

    @unittest.skipUnless(isprime, "sympy not found in sys.modules")
    def test_crypto_key_share_ffdhe_coprimes(self):
        for ffdhe_group in (
            NamedGroup.ffdhe2048,
            NamedGroup.ffdhe3072,
            NamedGroup.ffdhe4096,
            NamedGroup.ffdhe6144,
            NamedGroup.ffdhe8192
        ):
            with self.subTest(named_group=ffdhe_group):
                FFDHE = TLSKeyExchange[ffdhe_group]  # noqa: N806
                self.assertTrue(FFDHE.q == FFDHE.p // 2, "q must equal 2*p+1")
                self.assertTrue(isprime(FFDHE.p), "p must be a prime number")
                self.assertTrue(isprime(FFDHE.q), "p must be a prime number")
