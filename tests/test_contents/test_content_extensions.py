from siotls.contents import alerts
from siotls.contents.handshakes.extensions import (
    ALPN,
    Extension,
    HostName,
    KeyShareRequest,
    MaxFragmentLength,
    OCSPStatusRequest,
    PostHandshakeAuth,
    PskKeyExchangeModes,
    ServerNameListRequest,
    SignatureAlgorithms,
    SupportedGroups,
    SupportedVersionsRequest,
)
from siotls.iana import (
    HandshakeType,
    MaxFragmentLengthCode,
    MaxFragmentLengthOctets,
    NamedGroup,
    PskKeyExchangeMode,
    SignatureScheme,
    TLSVersion,
)
from siotls.serial import SerialIO

from . import TestContent


class TestContentExtension(TestContent):
    def parse_extension(self, payload):
        stream = SerialIO(payload)
        ext = Extension.parse(stream, handshake_type=HandshakeType.CLIENT_HELLO)
        self.assertTrue(stream.is_eof(), stream.read())
        return ext


class TestContentALPN(TestContentExtension):
    def test_content_alpn_io(self):
        payload = bytes.fromhex("0010000e000c02683208687474702f312e31")
        ext = self.parse_extension(payload)
        self.assertEqual(ext, ALPN(["h2", "http/1.1"]))
        self.assertEqual(ext.serialize(), payload)


class TestContentKeyShare(TestContentExtension):
    def test_content_key_share_io(self):
        payload = bytes.fromhex("""
            003300260024001d0020ad4061d3f71e40a1bacce42538e303abadbc2c9485fabb
            fada051b859e5e961b
        """)
        ext = self.parse_extension(payload)
        self.assertEqual(ext, KeyShareRequest({
            NamedGroup.x25519: bytes.fromhex("""
                ad4061d3f71e40a1bacce42538e303abadbc2c9485fabbfada051b859e5e96
                1b
            """),
        }))
        self.assertEqual(ext.serialize(), payload)


class TestContentMaxFragmentLength(TestContentExtension):
    def test_content_max_fragment_length_io(self):
        payload = bytes.fromhex("0001000101")
        ext = self.parse_extension(payload)
        self.assertEqual(ext, MaxFragmentLength(MaxFragmentLengthCode.MAX_512))
        self.assertEqual(ext.serialize(), payload)

    def test_content_max_fragment_length_io_bad_code(self):
        payload = bytes.fromhex("0001000100")
        with self.assertRaises(alerts.IllegalParameter):
            self.parse_extension(payload)

    def test_content_max_fragment_length_init_code_and_octets(self):
        e = "the code and octets arguments are mutualy exclusive"
        with self.assertRaises(ValueError, error_msg=e):
            MaxFragmentLength(
                code=MaxFragmentLengthCode.MAX_512,
                octets=MaxFragmentLengthOctets.MAX_512,
            )

    def test_content_max_fragment_length_init_neither_code_nor_octets(self):
        e = "missing code or octets arguments"
        with self.assertRaises(ValueError, error_msg=e):
            MaxFragmentLength()

    def test_content_max_fragment_length_reflexion(self):
        mfl = MaxFragmentLength(code=MaxFragmentLengthCode.MAX_512)
        self.assertEqual(mfl.code, MaxFragmentLengthCode.MAX_512)
        self.assertEqual(mfl.octets, MaxFragmentLengthOctets.MAX_512)


class TestContentPostHandshakeAuth(TestContentExtension):
    def test_content_post_handshake_auth_io(self):
        payload = bytes.fromhex("00310000")
        ext = self.parse_extension(payload)
        self.assertEqual(ext, PostHandshakeAuth())
        self.assertEqual(ext.serialize(), payload)


class TestContentPostSignatureAlgorithms(TestContentExtension):
    def test_content_post_signature_algorithms_io(self):
        payload = bytes.fromhex("""
            000d001e001c040305030603080708080809080a080b0804080508060401050106
            01
        """)
        ext = self.parse_extension(payload)
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
        self.assertEqual(ext.serialize(), payload)


class TestContentPskKeyExchangeModes(TestContentExtension):
    def test_content_psk_key_exchange_modes_io(self):
        payload = bytes.fromhex("002d00020101")
        ext = self.parse_extension(payload)
        self.assertEqual(ext, PskKeyExchangeModes([
            PskKeyExchangeMode.PSK_DHE_KE
        ]))
        self.assertEqual(ext.serialize(), payload)


class TestContentServerName(TestContentExtension):
    def test_content_server_name_io(self):
        payload = bytes.fromhex("0000000e000c0000096c6f63616c686f7374")
        ext = self.parse_extension(payload)
        self.assertEqual(ext, ServerNameListRequest([HostName("localhost")]))
        self.assertEqual(ext.serialize(), payload)


class TestContentSupportedGroup(TestContentExtension):
    def test_content_supported_group_io(self):
        payload = bytes.fromhex("""
            000a00160014001d0017001e0019001801000101010201030104
        """)
        ext = self.parse_extension(payload)
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
        self.assertEqual(ext.serialize(), payload)


class TestContentSupportedVersions(TestContentExtension):
    def test_content_supported_versions_io(self):
        payload = bytes.fromhex("002b0003020304")
        ext = self.parse_extension(payload)
        self.assertEqual(ext, SupportedVersionsRequest([TLSVersion.TLS_1_3]))
        self.assertEqual(ext.serialize(), payload)


class TestContentStatusRequest(TestContentExtension):
    def test_content_status_request_io(self):
        payload = bytes.fromhex("000500050100000000")
        ext = self.parse_extension(payload)
        self.assertEqual(ext, OCSPStatusRequest(
            responder_id_list=[],
            request_extensions=b"",
        ))
