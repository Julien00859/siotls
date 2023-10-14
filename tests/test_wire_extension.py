import unittest
from siotls.contents.handshakes.extensions import (
    Extension,
    ServerNameList, HostName,
    SupportedGroups,
    SignatureAlgorithms,
    ApplicationLayerProtocolNegotiation,
    SupportedVersionsRequest,
    PskKeyExchangeModes,
    PostHandshakeAuth,
    KeyShareRequest, KeyShareEntry,
)
from siotls.iana import (
    HandshakeType,
    NamedGroup,
    SignatureScheme,
    PskKeyExchangeMode,
    TLSVersion,
)
from siotls.serial import SerialIO


def parse_extension(stream):
    return Extension.parse(stream, handshake_type=HandshakeType.CLIENT_HELLO)


class TestWireExtension(unittest.TestCase):

    def test_wire_extension_0000_server_name0(self):
        payload = "0000000e000c0000096c6f63616c686f7374"
        stream = SerialIO(bytes.fromhex(payload))
        ext = parse_extension(stream)
        self.assertEqual(stream.read(), b'', "stream should be at end of file")
        self.assertEqual(ext, ServerNameList([HostName("localhost")]))
        self.assertEqual(ext.serialize().hex(), payload)

    def test_wire_extension_000a_supported_group0(self):
        payload = "000a00160014001d0017001e0019001801000101010201030104"
        stream = SerialIO(bytes.fromhex(payload))
        ext = parse_extension(stream)
        self.assertEqual(stream.read(), b'', "stream should be at end of file")
        self.assertEqual(ext, SupportedGroups([
            NamedGroup.x25519,
            NamedGroup.secp256r1,
            NamedGroup.x448,
            NamedGroup.secp521r1,
            NamedGroup.secp384r1,
            NamedGroup.ffdhe2048,
            NamedGroup.ffdhe3072,
            NamedGroup.ffdhe4096,
            NamedGroup.ffdhe6144,
            NamedGroup.ffdhe8192,
        ]))
        self.assertEqual(ext.serialize().hex(), payload)

    def test_wire_extension_000d_post_signature_algorithms0(self):
        payload = ''.join("""
            000d001e001c040305030603080708080809080a080b0804080508060401050106
            01
        """.split())
        stream = SerialIO(bytes.fromhex(payload))
        ext = parse_extension(stream)
        self.assertEqual(stream.read(), b'', "stream should be at end of file")
        self.assertEqual(ext, SignatureAlgorithms([
            SignatureScheme.ecdsa_secp256r1_sha256,
            SignatureScheme.ecdsa_secp384r1_sha384,
            SignatureScheme.ecdsa_secp521r1_sha512,
            SignatureScheme.ed25519,
            SignatureScheme.ed448,
            SignatureScheme.rsa_pss_pss_sha256,
            SignatureScheme.rsa_pss_pss_sha384,
            SignatureScheme.rsa_pss_pss_sha512,
            SignatureScheme.rsa_pss_rsae_sha256,
            SignatureScheme.rsa_pss_rsae_sha384,
            SignatureScheme.rsa_pss_rsae_sha512,
            SignatureScheme.rsa_pkcs1_sha256,
            SignatureScheme.rsa_pkcs1_sha384,
            SignatureScheme.rsa_pkcs1_sha512,
        ]))
        self.assertEqual(ext.serialize().hex(), payload)

    def test_wire_extension_0010_application_layer_protocol_negotiation0(self):
        payload = "0010000e000c02683208687474702f312e31"
        stream = SerialIO(bytes.fromhex(payload))
        ext = parse_extension(stream)
        self.assertEqual(stream.read(), b'', "stream should be at end of file")
        self.assertEqual(ext, ApplicationLayerProtocolNegotiation([
            "h2", "http/1.1"
        ]))
        self.assertEqual(ext.serialize().hex(), payload)

    def test_wire_extension_002b_supported_versions0(self):
        payload = "002b0003020304"
        stream = SerialIO(bytes.fromhex(payload))
        ext = parse_extension(stream)
        self.assertEqual(stream.read(), b'', "stream should be at end of file")
        self.assertEqual(ext, SupportedVersionsRequest([TLSVersion.TLS_1_3]))
        self.assertEqual(ext.serialize().hex(), payload)

    def test_wire_extension_002d_psk_key_exchange_modes0(self):
        payload = "002d00020101"
        stream = SerialIO(bytes.fromhex(payload))
        ext = parse_extension(stream)
        self.assertEqual(stream.read(), b'', "stream should be at end of file")
        self.assertEqual(ext, PskKeyExchangeModes([
            PskKeyExchangeMode.PSK_DHE_KE
        ]))
        self.assertEqual(ext.serialize().hex(), payload)

    def test_wire_extension_0031_post_handshake_auth0(self):
        payload = "00310000"
        stream = SerialIO(bytes.fromhex(payload))
        ext = parse_extension(stream)
        self.assertEqual(stream.read(), b'', "stream should be at end of file")
        self.assertEqual(ext, PostHandshakeAuth())
        self.assertEqual(ext.serialize().hex(), payload)

    def test_wire_extension_0033_key_share0(self):
        payload = ''.join("""
            003300260024001d0020ad4061d3f71e40a1bacce42538e303abadbc2c9485fabb
            fada051b859e5e961b
        """.split())
        stream = SerialIO(bytes.fromhex(payload))
        ext = parse_extension(stream)
        self.assertEqual(stream.read(), b'', "stream should be at end of file")
        self.assertEqual(ext, KeyShareRequest([
            KeyShareEntry(
                NamedGroup.x25519,
                bytes.fromhex("""
                    ad4061d3f71e40a1bacce42538e303abadbc2c9485fabbfada051b859e
                    5e961b
                """),
            ),
        ]))
        self.assertEqual(ext.serialize().hex(), payload)
