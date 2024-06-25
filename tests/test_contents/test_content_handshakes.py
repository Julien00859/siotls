import contextlib
import logging
from datetime import datetime, timedelta, timezone

from freezegun import freeze_time

from siotls.contents import alerts
from siotls.contents.handshakes import (
    ClientHello,
    EncryptedExtensions,
    Handshake,
    NewSessionTicket,
)
from siotls.contents.handshakes.extensions import (
    Cookie,
    Heartbeat,
    PreSharedKeyRequest,
    PskIdentity,
    PskKeyExchangeModes,
)
from siotls.iana import (
    CipherSuites,
    ExtensionType,
    HeartbeatMode,
    PskKeyExchangeMode,
    TLSVersion,
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


class TestContentBadHandshake(TestContentHandshake):
    def test_content_bad_handshake(self):
        stream = SerialIO()
        stream.write_int(1, 0)  # invalid handshake type
        stream.write_int(3, 0)  # length
        stream.seek(0)

        e = "0 is not a valid HandshakeType"
        with self.assertRaises(alerts.IllegalParameter, error_msg=e):
            Handshake.parse(stream)


class TestContentHandshakeClientHello(TestContentHandshake):
    def test_content_client_hello_io(self):
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

    def test_content_client_hello_io_bad_version(self):
        stream = SerialIO()
        stream.write_int(2, TLSVersion.TLS_1_1)
        stream.seek(0)

        e = f"expected {TLSVersion.TLS_1_2} but {TLSVersion.TLS_1_1} found"
        with self.assertRaises(alerts.ProtocolVersion, error_msg=e):
            ClientHello.parse_body(stream)

    def test_content_client_hello_io_bad_compression_method(self):
        stream = SerialIO()
        stream.write_int(2, TLSVersion.TLS_1_2)
        stream.write(b"random--" * 4)
        stream.write_var(1, b"legacy session id")
        stream.write_listint(2, 2, [CipherSuites.TLS_AES_128_GCM_SHA256])
        pos = stream.tell()

        with self.subTest(msg="empty compression method list"):
            stream.seek(pos)
            stream.truncate()
            stream.write_listint(1, 1, [])  # empty compression method list
            stream.seek(0)
            e = "only the NULL compression method is supported in TLS 1.3"
            with self.assertRaises(alerts.IllegalParameter, error_msg=e):
                ClientHello.parse_body(stream)

        with self.subTest(msg="empty compression method list"):
            stream.seek(pos)
            stream.truncate()
            null, deflate = 0, 1  # RFC3749
            stream.write_listint(1, 1, [deflate, null])
            stream.seek(0)
            e = "only the NULL compression method is supported in TLS 1.3"
            with self.assertRaises(alerts.IllegalParameter, error_msg=e):
                ClientHello.parse_body(stream)

    def test_content_client_hello_io_reraise_value_error(self):
        stream = SerialIO()
        stream.write_int(2, TLSVersion.TLS_1_2)
        stream.write(b"random--" * 4)
        stream.write_var(1, b"legacy session id")
        stream.write_listint(2, 2, [])  # empty cipher suite <-- the error
        stream.write_listint(1, 1, [0])  # NULL compression method
        stream.write_var(2, b"")  # no extensions
        stream.seek(0)

        e = "cipher suites cannot be empty"
        with self.assertRaises(alerts.IllegalParameter, error_msg=e):
            ClientHello.parse_body(stream)

    def test_content_client_hello_io_bad_extension(self):
        stream = SerialIO()
        stream.write_int(2, TLSVersion.TLS_1_2)
        stream.write(b"random--" * 4)
        stream.write_var(1, b"legacy session id")
        stream.write_listint(2, 2, [CipherSuites.TLS_AES_128_GCM_SHA256])
        stream.write_listint(1, 1, [0])  # NULL compression method
        stream.write_int(2, 3)  # extension length
        stream.write_int(2, ExtensionType.OID_FILTERS)  # bad extension for client hello
        stream.write_var(2, b"")  # empty data, which we don't actually care here
        stream.seek(0)

        e =("cannot receive extension <ExtensionType.OID_FILTERS: 48 (0x0030)>"
            " with handshake CLIENT_HELLO")
        with self.assertRaises(alerts.IllegalParameter, error_msg=e):
            ClientHello.parse_body(stream)

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
                extensions=[
                    Cookie('foo'),
                    Heartbeat(HeartbeatMode.PEER_ALLOWED_TO_SEND),
                    Cookie('bar'),
                ]
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
    def test_content_encryted_extensions_io(self):
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


class TestContentHandshakeNewSessionTicket(TestContentHandshake):
    @freeze_time("2024-06-25 13:00:00")
    def test_content_new_session_ticket_io(self):
        payload = bytes.fromhex("""
            040001050000012c61e0fa6808000000000000000100f0c71bf2a7b648cc0b55ca
            3e62b94e34c3814754d623e25cefeeb32af4fec33e0652f67a4a384f215e2c534d
            03b577820a1f990e90843931403dce2f7e53aa57c82282490f09b5f3796fb85083
            4aeaa4c5a7c53294d51db63ca095f3e817a180527a41523cc7726ea94394e4ced6
            d49ff7f733c4d28c4f6185cf98f0663736393532febbdf2fbbee83ed8df061f8c1
            bda47eef4785604b976ad386da64a043b3f2162ce961c13680ed70e8b95543b1ad
            fd24427a8f2629d1efc8704533628c9e5eb7a4d088472875cf2a6baf9bbb1eb500
            2a722cba4338864ff87f605bd0341b5aa0dacaa2d91e59fb7e5fea044a0e749800
            00
        """)
        stream = SerialIO(payload)
        handshake = NewSessionTicket.parse(stream)
        self.assertTrue(stream.is_eof())

        new_session_ticket = NewSessionTicket(
            ticket_expires=datetime.now(timezone.utc) + timedelta(minutes=5),
            ticket_age_add=1642134120,
            ticket_nonce=(1).to_bytes(8, 'big'),
            ticket=payload[23:23+240],
            extensions=[],
        )
        self.assertEqual(handshake, new_session_ticket)

        self.assertEqual(handshake.serialize(), payload)
