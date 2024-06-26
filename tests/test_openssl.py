import contextlib
import dataclasses
import ssl
import unittest
from os import fspath

from parameterized import parameterized

from siotls import TLSConnection
from siotls.iana import CipherSuites, NamedGroup

from . import TAG_INTEGRATION, TestCase, test_pem_dir
from .config import client_config, server_config


@unittest.skipUnless(TAG_INTEGRATION, "enable with SIOTLS_INTEGRATION=1")
class TestOpenSSL(TestCase):
    def _test_openssl_client(self, cipher, key_exchange):
        context = ssl.create_default_context(
            cafile=fspath(test_pem_dir.joinpath('ca-cert.pem'))
        )
        openssl_in = siotls_out = ssl.MemoryBIO()
        openssl_out = siotls_in = ssl.MemoryBIO()
        openssl_sock = context.wrap_bio(openssl_in, openssl_out)

        config = dataclasses.replace(
            server_config,
            cipher_suites=[cipher],
            key_exchanges=[key_exchange],
        )
        conn = TLSConnection(config)
        conn.initiate_connection()

        # ClientHello
        with contextlib.suppress(ssl.SSLWantReadError):
            openssl_sock.do_handshake()
        conn.receive_data(siotls_in.read())
        siotls_out.write(conn.data_to_send())

        if key_exchange != NamedGroup.x25519:
            # ClientHello again after HelloRetryRequest
            with contextlib.suppress(ssl.SSLWantReadError):
                openssl_sock.do_handshake()
            conn.receive_data(siotls_in.read())
            siotls_out.write(conn.data_to_send())

        # Finished after ServerHello/Cert/CertVerify/Finished
        openssl_sock.do_handshake()
        conn.receive_data(siotls_in.read())
        siotls_out.write(conn.data_to_send())

        # Connection established, exchange a ping pong
        self.assertTrue(conn.is_post_handshake())
        openssl_sock.write(b"ping!\n")
        conn.receive_data(siotls_in.read())
        self.assertEqual(conn.data_to_read(), b"ping!\n")
        conn.send_data(b"pong!\n")
        siotls_out.write(conn.data_to_send())
        self.assertEqual(openssl_sock.read(), b"pong!\n")

    @parameterized.expand([
        (cipher.name[4:], cipher)
        for cipher in [
            CipherSuites.TLS_AES_128_GCM_SHA256,
            CipherSuites.TLS_AES_256_GCM_SHA384,
            CipherSuites.TLS_CHACHA20_POLY1305_SHA256,
        ]
    ])
    def test_openssl_client_cipher(self, _, cipher):
        group = NamedGroup.x25519
        self._test_openssl_client(cipher, group)

    @parameterized.expand([(group.name, group) for group in NamedGroup])
    def test_openssl_client_group(self, _, group):
        cipher = CipherSuites.TLS_CHACHA20_POLY1305_SHA256
        self._test_openssl_client(cipher, group)


    def _test_openssl_server(self, cipher, key_exchange):
        context = ssl.create_default_context(
            purpose=ssl.Purpose.CLIENT_AUTH,
            cafile=fspath(test_pem_dir.joinpath('ca-cert.pem'))
        )
        context.load_cert_chain(
            fspath(test_pem_dir.joinpath('server-cert.pem')),
            fspath(test_pem_dir.joinpath('server-privkey.pem')),
        )
        openssl_in = siotls_out = ssl.MemoryBIO()
        openssl_out = siotls_in = ssl.MemoryBIO()
        openssl_sock = context.wrap_bio(openssl_in, openssl_out, server_side=True)

        config = dataclasses.replace(
            client_config,
            cipher_suites=[cipher],
            key_exchanges=[key_exchange],
        )
        conn = TLSConnection(config, server_hostname='server.siotls.localhost')

        # ClientHello
        conn.initiate_connection()
        siotls_out.write(conn.data_to_send())

        with contextlib.suppress(ssl.SSLWantReadError):
            openssl_sock.do_handshake()
        conn.receive_data(siotls_in.read())
        siotls_out.write(conn.data_to_send())

        # Finished after ServerHello/Cert/CertVerify/Finished
        openssl_sock.do_handshake()

        # Connection established, exchange a ping pong
        self.assertTrue(conn.is_post_handshake())
        openssl_sock.write(b"ping!\n")
        conn.receive_data(siotls_in.read())
        self.assertEqual(conn.data_to_read(), b"ping!\n")
        conn.send_data(b"pong!\n")
        siotls_out.write(conn.data_to_send())
        self.assertEqual(openssl_sock.read(), b"pong!\n")

    @parameterized.expand([
        (cipher.name[4:], cipher)
        for cipher in [
            CipherSuites.TLS_AES_128_GCM_SHA256,
            CipherSuites.TLS_AES_256_GCM_SHA384,
            CipherSuites.TLS_CHACHA20_POLY1305_SHA256,
        ]
    ])
    def test_openssl_server_cipher(self, _, cipher):
        group = NamedGroup.x25519
        self._test_openssl_server(cipher, group)

    @parameterized.expand([(group.name, group) for group in NamedGroup])
    def test_openssl_server_group(self, _, group):
        cipher = CipherSuites.TLS_CHACHA20_POLY1305_SHA256
        self._test_openssl_server(cipher, group)
