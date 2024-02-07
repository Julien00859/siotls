import unittest

from siotls.crypto.key_share import init, resume
from siotls.iana import NamedGroup


@unittest.skip("not fully implemented")
class TestCryptoKeyShare(unittest.TestCase):

    def test_crypto_key_share(self):
        for key_exchange in NamedGroup:
            with self.subTest(key_exchange=key_exchange):
                client_priv, client_pub = init(key_exchange)
                server_shared, server_pub = resume(key_exchange, None, client_pub)
                client_shared, _ = resume(key_exchange, client_priv, server_pub)
                self.assertEqual(server_shared, client_shared)
