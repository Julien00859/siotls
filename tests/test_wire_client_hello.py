import unittest
from siotls.contents.handshakes import Handshake, ClientHello
from siotls.iana import (
    HandshakeType,
    ExtensionType,
    TLSVersion,
    CipherSuites,
)
from siotls.serial import SerialIO
from siotls.utils import hexdump


class TestWireExtension(unittest.TestCase):

    def test_wire_client_hello0_parsing(self):
        payload = "".join("""
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
        """.split())
        stream = SerialIO(bytes.fromhex(payload))

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

        # only test for the extensions types, not their payload
        handshake.extensions = list(handshake.extensions.keys())
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
        self.assertEqual(handshake, client_hello)


    def test_wire_client_hello1_serialization(self):
        payload = "".join("""
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
        """.split())
        stream = SerialIO(bytes.fromhex(payload))

        handshake = Handshake.parse(stream)
        self.assertTrue(stream.is_eof(), stream.read())

        self.maxDiff = None
        self.assertEqual(handshake.serialize().hex(), payload)
