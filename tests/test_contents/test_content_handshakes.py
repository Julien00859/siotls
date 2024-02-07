import contextlib
import logging

from siotls.contents.handshakes import (
    ClientHello,
    EncryptedExtensions,
    Handshake,
)
from siotls.contents.handshakes.extensions import (
    Cookie,
    PreSharedKeyRequest,
    PskIdentity,
    PskKeyExchangeModes,
)
from siotls.iana import (
    CipherSuites,
    ExtensionType,
    PskKeyExchangeMode,
)
from siotls.serial import SerialIO

from . import TestContent


class TestContentHandshake(TestContent):
    @contextlib.contextmanager
    def neuter_extension(self, handshake, attr='extensions'):
        extensions = getattr(handshake, attr)
        setattr(handshake, attr, list(extensions.keys()))
        yield
        setattr(handshake, attr, extensions)


class TestContentHandshakeClientHello(TestContentHandshake):
    def test_content_client_hello(self):
        payload = bytes.fromhex("""
            010001fc03033019520a80cf1a5b038de9c17e6a7f376425194f6cdaf8df484f64
            6d930ee35f207cd20364a3a6731c7882bc433cc5cbb1f0b091e735bff00d95007e
            e5348d9f74000813021303130100ff010001ab0000000f000d00000a6c6f63616c
            686f737432000b000403000102000a00160014001d0017001e0019001801000101
            010201030104337400000010000e000c02683208687474702f312e310016000000
            17000000310000000d001e001c040305030603080708080809080a080b08040805
            0806040105010601002b0003020304002d00020101003300260024001d0020a9da
            4a99bec4360f651b5fc3cb3f88ad8cdb1bb61bfe327d34b715ec40ca2777001500
            f70000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000
            000000000000000000000000000000000000000000000000000000000000000000
            0000000000000000000000000000000000
        """)

        stream = SerialIO(payload)
        handshake = Handshake.parse(stream)
        self.assertTrue(stream.is_eof(), stream.read())

        client_hello = ClientHello(
            random=bytes.fromhex("""
                3019520a80cf1a5b038de9c17e6a7f376425194f6cdaf8df484f646d930ee3
                5f
            """),
            cipher_suites=[
                CipherSuites.TLS_AES_256_GCM_SHA384,
                CipherSuites.TLS_CHACHA20_POLY1305_SHA256,
                CipherSuites.TLS_AES_128_GCM_SHA256,
                CipherSuites.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
            ],
            extensions={},  # set below
        )
        client_hello.legacy_session_id=bytes.fromhex("""
            7cd20364a3a6731c7882bc433cc5cbb1f0b091e735bff00d95007ee5348d9f74
        """)
        client_hello.extensions = [
            ExtensionType.SERVER_NAME,
            0xb,  # ex point formats
            ExtensionType.SUPPORTED_GROUPS,
            0x3374,  # next protocol negociation
            ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            0x16,  # encrypt then mac
            0x17,  # extended master secret
            ExtensionType.POST_HANDSHAKE_AUTH,
            ExtensionType.SIGNATURE_ALGORITHMS,
            ExtensionType.SUPPORTED_VERSIONS,
            ExtensionType.PSK_KEY_EXCHANGE_MODES,
            ExtensionType.KEY_SHARE,
            ExtensionType.PADDING,
        ]
        with self.neuter_extension(handshake):
            self.assertEqual(handshake, client_hello)

        self.assertEqual(handshake.serialize(), payload)

    def test_content_client_hello_bad_random(self):
        e = "random must be exactly 32 bytes longs"
        with self.assertRaises(ValueError, error_msg=e):
            ClientHello(
                random=b'bad random',
                cipher_suites=[CipherSuites.TLS_AES_128_GCM_SHA256],
                extensions=[]
            )

    def test_content_client_hello_empty_cipher_suites(self):
        e = "cipher suites cannot be empty"
        with self.assertRaises(ValueError, error_msg=e):
            ClientHello(
                random=b'a' * 32,
                cipher_suites=[],
                extensions=[]
            )

    def test_content_client_hello_duplicated_different_extensions(self):
        e = "duplicated extension: Cookie(cookie='foo') vs Cookie(cookie='bar')"
        with self.assertRaises(ValueError, error_msg=e):
            ClientHello(
                random=b'a' * 32,
                cipher_suites=[CipherSuites.TLS_AES_128_GCM_SHA256],
                extensions=[Cookie('foo'), Cookie('bar')]
            )

    def test_content_client_hello_duplicated_identic_extensions(self):
        logger = 'siotls.contents.handshakes.client_hello'
        w = "duplicated extension: Cookie(cookie='foo')"
        with self.assertLogs(logger, logging.WARNING, log_msg=w):
            ClientHello(
                random=b'a' * 32,
                cipher_suites=[CipherSuites.TLS_AES_128_GCM_SHA256],
                extensions=[Cookie('foo'), Cookie('foo')]
            )

    def test_content_client_hello_psk_not_last(self):
        e = "PreSharedKey() must be the last extension of the list"
        with self.assertRaises(ValueError, error_msg=e):
            ClientHello(
                random=b'a' * 32,
                cipher_suites=[CipherSuites.TLS_AES_128_GCM_SHA256],
                extensions=[
                    PreSharedKeyRequest([PskIdentity(b'', 0)], b''),
                    Cookie('bar')
                ]
            )

    def test_content_client_hello_missing_psk_exchange_mode(self):
        e = "missing mandatory extension: PskKeyExchangeModes()"
        with self.assertRaises(ValueError, error_msg=e):
            ClientHello(
                random=b'a' * 32,
                cipher_suites=[CipherSuites.TLS_AES_128_GCM_SHA256],
                extensions=[
                    PreSharedKeyRequest([PskIdentity(b'', 0)], b''),
                ]
            )

    def test_content_client_hello_valid_psk(self):
        ClientHello(
            random=b'a' * 32,
            cipher_suites=[CipherSuites.TLS_AES_128_GCM_SHA256],
            extensions=[
                PskKeyExchangeModes(PskKeyExchangeMode.PSK_DHE_KE),
                PreSharedKeyRequest([PskIdentity(b'', 0)], b''),
            ]
        )

class TestContentHandshakeEncryptedExtensions(TestContentHandshake):
    def test_content_encryted_extensions(self):
        payload = bytes.fromhex("0800000f000d00000000001000050003026832")
        stream = SerialIO(payload)
        handshake = EncryptedExtensions.parse(stream)
        self.assertTrue(stream.is_eof())

        ee = EncryptedExtensions({})
        ee.extensions = [
            ExtensionType.SERVER_NAME,
            ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION
        ]
        with self.neuter_extension(handshake):
            self.assertEqual(handshake, ee)

        self.assertEqual(handshake.serialize(), payload)
