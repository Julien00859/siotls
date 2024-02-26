import dataclasses
import unittest
import unittest.mock

from siotls.configuration import TLSConfiguration, TLSNegociatedConfiguration
from siotls.connection import TLSConnection
from siotls.contents import alerts
from siotls.contents.handshakes.extensions import (
    ALPN,
    Heartbeat,
    KeyShareRequest,
    KeyShareResponse,
    KeyShareRetry,
    MaxFragmentLength,
    SignatureAlgorithms,
    SupportedGroups,
    SupportedVersionsRequest,
    SupportedVersionsResponse,
)
from siotls.iana import (
    CipherSuites,
    ExtensionType,
    HeartbeatMode,
    MaxFragmentLengthOctets,
    NamedGroup,
    SignatureScheme,
    TLSVersion,
)
from siotls.states import ClientWaitServerHello, ServerWaitClientHello

from . import TestCase

# ----------------------------------------------------------------------
# Server-side, upon receiving ClientHello
# ----------------------------------------------------------------------

class TestNegociationServer(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = TLSConnection(TLSConfiguration('server'))
        cls.server._state = ServerWaitClientHello(cls.server)

    def setUp(self):
        self.server.nconfig = TLSNegociatedConfiguration(
            self.server.config.cipher_suites[0]
        )

    @classmethod
    def replace_config(cls, **kwargs):
        cls.server.config = dataclasses.replace(cls.server.config, **kwargs)


class TestNegociationServerCipherSuite(TestNegociationServer):
    def setUp(self):
        self.replace_config(cipher_suites=[
            CipherSuites.TLS_CHACHA20_POLY1305_SHA256,
            CipherSuites.TLS_AES_256_GCM_SHA384,
            CipherSuites.TLS_AES_128_GCM_SHA256,
        ])
        self.server.nconfig = None

    # Cipher suite isn't an extension, is part of the ClientHello header
    # hence cannot be missing.

    def test_negociation_server_ciper_suite_empty(self):
        e = "no common cipher suite found"
        with self.assertRaises(alerts.HandshakeFailure, error_msg=e):
            self.server._state._find_common_cipher_suite([])

    def test_negociation_server_cipher_suite_no_match(self):
        e = "no common cipher suite found"
        with self.assertRaises(alerts.HandshakeFailure, error_msg=e):
            self.server._state._find_common_cipher_suite([
                CipherSuites.TLS_AES_128_CCM_SHA256,
            ])

    def test_negociation_server_cipher_suite_pick_only_match(self):
        cipher_suite = self.server._state._find_common_cipher_suite([
            CipherSuites.TLS_AES_128_GCM_SHA256,
            CipherSuites.TLS_AES_128_CCM_SHA256,
        ])
        self.assertEqual(cipher_suite, CipherSuites.TLS_AES_128_GCM_SHA256)

    def test_negociation_server_supported_groups_pick_server_best(self):
        cipher_suite = self.server._state._find_common_cipher_suite([
            CipherSuites.TLS_AES_128_CCM_SHA256,
            CipherSuites.TLS_AES_128_GCM_SHA256,
            CipherSuites.TLS_AES_256_GCM_SHA384,
        ])
        self.assertEqual(cipher_suite, CipherSuites.TLS_AES_256_GCM_SHA384)


class TestNegociationServerSupportedVersions(TestNegociationServer):
    def test_negociation_server_supported_versions_missing(self):
        e = "client doesn't support TLS 1.3"
        with self.assertRaises(alerts.ProtocolVersion, error_msg=e):
            self.server._state._negociate_supported_versions(None)

    def test_negociation_server_supported_versions_too_old(self):
        e = "client doesn't support TLS 1.3"
        with self.assertRaises(alerts.ProtocolVersion, error_msg=e):
            self.server._state._negociate_supported_versions(
                SupportedVersionsRequest([TLSVersion.TLS_1_2])
            )

    def test_negociation_server_supported_versions_too_new(self):
        e = "client doesn't support TLS 1.3"
        with self.assertRaises(alerts.ProtocolVersion, error_msg=e):
            self.server._state._negociate_supported_versions(
                SupportedVersionsRequest([0x0305])  # TLS 1.4.TLS_1_2
            )

    def test_negociation_server_supported_versions_single(self):
        clears, crypts = self.server._state._negociate_supported_versions(
            SupportedVersionsRequest([TLSVersion.TLS_1_3])
        )
        self.assertEqual(clears, [SupportedVersionsResponse(TLSVersion.TLS_1_3)])
        self.assertEqual(crypts, [])

    def test_negociation_server_supported_versions_multiple(self):
        clears, crypts = self.server._state._negociate_supported_versions(
            SupportedVersionsRequest([
                TLSVersion.TLS_1_2,
                TLSVersion.TLS_1_3,
                0x0305,  # TLS 1.4
            ])
        )
        self.assertEqual(clears, [SupportedVersionsResponse(TLSVersion.TLS_1_3)])
        self.assertEqual(crypts, [])


class TestNegociationServerSupportedGroups(TestNegociationServer):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.replace_config(key_exchanges=[NamedGroup.x25519, NamedGroup.secp256r1])

    def test_negociation_server_supported_groups_missing(self):
        e = ExtensionType.SUPPORTED_GROUPS
        with self.assertRaises(alerts.MissingExtension, error_msg=e):
            self.server._state._negociate_supported_groups(None)

    def test_negociation_server_supported_groups_empty(self):
        e = "no common key exchange found"
        with self.assertRaises(alerts.HandshakeFailure, error_msg=e):
            self.server._state._negociate_supported_groups(SupportedGroups([]))

    def test_negociation_server_supported_groups_no_match(self):
        e = "no common key exchange found"
        with self.assertRaises(alerts.HandshakeFailure, error_msg=e):
            self.server._state._negociate_supported_groups(
                SupportedGroups([NamedGroup.x448])
            )

    def test_negociation_server_supported_groups_pick_single_match(self):
        clears, crypts = self.server._state._negociate_supported_groups(
            SupportedGroups([NamedGroup.x448, NamedGroup.x25519]),
        )
        self.assertEqual(clears, [])
        self.assertEqual(crypts, [])
        self.assertEqual(self.server.nconfig.key_exchange, NamedGroup.x25519)

    def test_negociation_server_supported_groups_pick_server_best(self):
        clears, crypts = self.server._state._negociate_supported_groups(
            SupportedGroups([
                NamedGroup.x448,
                NamedGroup.secp256r1,
                NamedGroup.x25519
            ]),
        )
        self.assertEqual(clears, [])
        self.assertEqual(crypts, [])
        self.assertEqual(self.server.nconfig.key_exchange, NamedGroup.x25519)


class TestNegociationServerSignatureAlgorithms(TestNegociationServer):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.replace_config(signature_algorithms=[
            SignatureScheme.ed25519,
            SignatureScheme.ecdsa_secp256r1_sha256,
        ])

    def test_negociation_server_signature_algorithms_missing(self):
        e = ExtensionType.SIGNATURE_ALGORITHMS
        with self.assertRaises(alerts.MissingExtension, error_msg=e):
            self.server._state._negociate_signature_algorithms(None)

    def test_negociation_server_signature_algorithms_empty(self):
        e = "no common digital signature found"
        with self.assertRaises(alerts.HandshakeFailure, error_msg=e):
            self.server._state._negociate_signature_algorithms(
                SignatureAlgorithms([])
            )

    def test_negociation_server_signature_algorithms_no_match(self):
        e = "no common digital signature found"
        with self.assertRaises(alerts.HandshakeFailure, error_msg=e):
            self.server._state._negociate_signature_algorithms(
                SignatureAlgorithms([SignatureScheme.ed448]),
            )

    def test_negociation_server_signature_algorithms_pick_single_match(self):
        clears, crypts = self.server._state._negociate_signature_algorithms(
            SignatureAlgorithms([
                SignatureScheme.ed448,
                SignatureScheme.ed25519
            ]),
        )
        self.assertEqual(clears, [])
        self.assertEqual(crypts, [])
        self.assertEqual(self.server.nconfig.signature_algorithm, SignatureScheme.ed25519)

    def test_negociation_server_signature_algorithms_pick_server_best(self):
        clears, crypts = self.server._state._negociate_signature_algorithms(
            SignatureAlgorithms([
                SignatureScheme.ed448,
                SignatureScheme.ecdsa_secp256r1_sha256,
                SignatureScheme.ed25519
            ]),
        )
        self.assertEqual(clears, [])
        self.assertEqual(crypts, [])
        self.assertEqual(self.server.nconfig.signature_algorithm, SignatureScheme.ed25519)


class TestNegociationServerKeyShare(TestNegociationServer):
    def test_negociation_server_key_share_missing_extension(self):
        self.server.nconfig.key_exchange = NamedGroup.x25519
        clears, crypts, shared_key = self.server._state._negociate_key_share(None)
        self.assertEqual(clears, [KeyShareRetry(NamedGroup.x25519)])
        self.assertEqual(crypts, [])
        self.assertFalse(shared_key)

    def test_negociation_server_key_share_missing_key_exchange(self):
        # Client supports both x25519 and x448 but sent key shares only
        # for x448. Server picked x25519 (its preference over x448) but
        # cannot resume key share.
        self.server.nconfig.key_exchange = NamedGroup.x25519
        clears, crypts, shared_key = self.server._state._negociate_key_share(
            KeyShareRequest({NamedGroup.x448: b''})
        )
        self.assertEqual(clears, [KeyShareRetry(NamedGroup.x25519)])
        self.assertEqual(crypts, [])
        self.assertFalse(shared_key)

    @unittest.mock.patch("siotls.states.server.wait_client_hello.key_share_resume")
    def test_negociation_server_key_share_mocked_share(self, key_share_resume):
        key_share_resume.return_value = (b'shared key', b'server share')
        self.server.nconfig.key_exchange = NamedGroup.x25519
        clears, crypts, shared_key = self.server._state._negociate_key_share(
            KeyShareRequest({NamedGroup.x25519: b'client share'})
        )
        key_share_resume.assert_called_once_with(NamedGroup.x25519, None, b'client share')
        self.assertEqual(clears, [KeyShareResponse(NamedGroup.x25519, b'server share')])
        self.assertEqual(crypts, [])
        self.assertEqual(shared_key, b'shared key')

    def test_negociation_server_key_share_corrupted_x(self):
        self.server.nconfig.key_exchange = NamedGroup.x25519
        e = "error while resuming key share"
        with self.assertRaises(alerts.HandshakeFailure, error_msg=e):
            self.server._state._negociate_key_share(
                KeyShareRequest({NamedGroup.x25519: b'bad key'})
            )

    def test_negociation_server_key_share_corrupted_ffdhe(self):
        self.server.nconfig.key_exchange = NamedGroup.ffdhe2048
        e = "error while resuming key share"
        with self.assertRaises(alerts.HandshakeFailure, error_msg=e):
            self.server._state._negociate_key_share(
                KeyShareRequest({NamedGroup.ffdhe2048: b'bad key' * 100})
            )

    def test_negociation_server_key_share_too_short_ffdhe(self):
        self.server.nconfig.key_exchange = NamedGroup.ffdhe2048
        e = "the peer's key is too short"
        with self.assertRaises(alerts.InsufficientSecurity, error_msg=e):
            self.server._state._negociate_key_share(
                KeyShareRequest({NamedGroup.ffdhe2048: b'too short key'})
            )


class TestNegociationServerMaxFragmentLength(TestNegociationServer):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.replace_config(max_fragment_length=MaxFragmentLengthOctets.MAX_16384)

    def test_negociation_server_max_fragment_length_missing(self):
        clears, crypts = self.server._state._negociate_max_fragment_length(None)
        self.assertEqual(clears, [])
        self.assertEqual(crypts, [])
        self.assertEqual(
            self.server.nconfig.max_fragment_length,
            MaxFragmentLengthOctets.MAX_16384
        )

    def test_negociation_server_max_fragment_length_valid(self):
        clears, crypts = self.server._state._negociate_max_fragment_length(
            MaxFragmentLength(octets=MaxFragmentLengthOctets.MAX_1024)
        )
        self.assertEqual(clears, [])
        self.assertEqual(crypts, [
            MaxFragmentLength(octets=MaxFragmentLengthOctets.MAX_1024),
        ])
        self.assertEqual(
            self.server.nconfig.max_fragment_length,
            MaxFragmentLengthOctets.MAX_1024,
        )


class TestNegociationServerALPN(TestNegociationServer):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.replace_config(alpn=['h2', 'http/1.1'])

    def _negociate_alpn(self, alpn_ext):
        return self.server._state._negociate_application_layer_protocol_negotiation(alpn_ext)

    def test_negociation_server_alpn_missing(self):
        clears, crypts = self._negociate_alpn(None)
        self.assertEqual(clears, [])
        self.assertEqual(crypts, [])
        self.assertIsNone(self.server.nconfig.alpn)

    def test_negociation_server_alpn_unconfigured(self):
        self.replace_config(alpn=None)
        clears, crypts = self._negociate_alpn(ALPN(['http/1.1']))
        self.assertEqual(clears, [])
        self.assertEqual(crypts, [])
        self.assertIsNone(self.server.nconfig.alpn)

    def test_negociation_server_alpn_pick_only_available(self):
        clears, crypts = self._negociate_alpn(ALPN(['http/1.1']))
        self.assertEqual(clears, [])
        self.assertEqual(crypts, [ALPN(['http/1.1'])])
        self.assertEqual(self.server.nconfig.alpn, 'http/1.1')

    def test_negociation_server_alpn_pick_server_best(self):
        clears, crypts = self._negociate_alpn(ALPN(['http/1.1', 'h2']))
        self.assertEqual(clears, [])
        self.assertEqual(crypts, [ALPN(['h2'])])
        self.assertEqual(self.server.nconfig.alpn, 'h2')

    def test_negociation_server_alpn_no_match(self):
        e = "no common application layer protocol found"
        with self.assertRaises(alerts.NoApplicationProtocol, error_msg=e):
            self._negociate_alpn(ALPN(['h3']))


class TestNegociationServerHeartbeat(TestNegociationServer):
    def test_negociation_server_heartbeat_missing(self):
        client_hb = None

        self.replace_config(can_echo_heartbeat=True)
        clears, crypts = self.server._state._negociate_heartbeat(client_hb)
        self.assertEqual(clears, [])
        self.assertEqual(crypts, [])
        self.assertFalse(self.server.nconfig.can_echo_heartbeat)
        self.assertFalse(self.server.nconfig.can_send_heartbeat)

        self.replace_config(can_echo_heartbeat=False)
        clears, crypts = self.server._state._negociate_heartbeat(client_hb)
        self.assertEqual(clears, [])
        self.assertEqual(crypts, [])
        self.assertFalse(self.server.nconfig.can_echo_heartbeat)
        self.assertFalse(self.server.nconfig.can_send_heartbeat)

    def test_negociation_server_heartbeat_client_allows_server_pings(self):
        client_hb = Heartbeat(HeartbeatMode.PEER_ALLOWED_TO_SEND)

        self.replace_config(can_echo_heartbeat=True)
        clears, crypts = self.server._state._negociate_heartbeat(client_hb)
        self.assertEqual(clears, [])
        self.assertEqual(crypts, [Heartbeat(HeartbeatMode.PEER_ALLOWED_TO_SEND)])
        self.assertTrue(self.server.nconfig.can_echo_heartbeat)
        self.assertTrue(self.server.nconfig.can_send_heartbeat)

        self.replace_config(can_echo_heartbeat=False)
        clears, crypts = self.server._state._negociate_heartbeat(client_hb)
        self.assertEqual(clears, [])
        self.assertEqual(crypts, [Heartbeat(HeartbeatMode.PEER_NOT_ALLOWED_TO_SEND)])
        self.assertFalse(self.server.nconfig.can_echo_heartbeat)
        self.assertTrue(self.server.nconfig.can_send_heartbeat)

    def test_negociation_server_heartbeat_client_refuses_server_pings(self):
        client_hb = Heartbeat(HeartbeatMode.PEER_NOT_ALLOWED_TO_SEND)

        self.replace_config(can_echo_heartbeat=True)
        clears, crypts = self.server._state._negociate_heartbeat(client_hb)
        self.assertEqual(clears, [])
        self.assertEqual(crypts, [Heartbeat(HeartbeatMode.PEER_ALLOWED_TO_SEND)])
        self.assertTrue(self.server.nconfig.can_echo_heartbeat)
        self.assertFalse(self.server.nconfig.can_send_heartbeat)

        self.replace_config(can_echo_heartbeat=False)
        clears, crypts = self.server._state._negociate_heartbeat(client_hb)
        self.assertEqual(clears, [])
        self.assertEqual(crypts, [Heartbeat(HeartbeatMode.PEER_NOT_ALLOWED_TO_SEND)])
        self.assertFalse(self.server.nconfig.can_echo_heartbeat)
        self.assertFalse(self.server.nconfig.can_send_heartbeat)


# ----------------------------------------------------------------------
# Client-side, upon receiving ServerHello
# ----------------------------------------------------------------------

class TestNegociationClient(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TLSConnection(TLSConfiguration('client'))
        cls.client._state = ClientWaitServerHello(cls.client, {})

    def setUp(self):
        self.client.nconfig = TLSNegociatedConfiguration(
            self.client.config.cipher_suites[0]
        )

    @classmethod
    def replace_config(cls, **kwargs):
        cls.client.config = dataclasses.replace(cls.client.config, **kwargs)


class TestNegociationClientSupportedVersions(TestNegociationClient):
    def test_negociation_client_supported_versions_missing(self):
        e = "the server doesn't support TLS 1.3"
        with self.assertRaises(alerts.ProtocolVersion, error_msg=e):
            self.client._state._negociate_supported_versions(None)

    def test_negociation_client_supported_versions_not_offered(self):
        e = "the server-selected supported version wasn't offered"
        with self.assertRaises(alerts.ProtocolVersion, error_msg=e):
            self.client._state._negociate_supported_versions(
                SupportedVersionsResponse(0x0305)  # TLS 1.4
            )

    def test_negociation_client_supported_versions_valid(self):
        self.client._state._negociate_supported_versions(
            SupportedVersionsResponse(TLSVersion.TLS_1_3)
        )


class TestNegociationClientKeyShare(TestNegociationClient):
    def test_negociation_client_key_share_missing(self):
        we_dont_care = None  # used as placeholder
        e = ExtensionType.KEY_SHARE
        with self.assertRaises(alerts.MissingExtension, error_msg=e):
            self.client._state._negociate_key_share(None, {
                NamedGroup.x25519: we_dont_care
            })

    def test_negociation_client_key_share_not_offered(self):
        we_dont_care = None  # used as placeholder
        e = "the server-selected key exchange wasn't offered"
        with self.assertRaises(alerts.IllegalParameter, error_msg=e):
            self.client._state._negociate_key_share(
                KeyShareResponse(NamedGroup.x448, we_dont_care),
                {NamedGroup.x25519: we_dont_care},
            )

    @unittest.mock.patch("siotls.states.client.wait_server_hello.key_share_resume")
    def test_negociation_client_key_share_bad_key(self, key_share_resume):
        key_share_resume.side_effect = ValueError()
        e = "error while resuming key share"
        with self.assertRaises(alerts.IllegalParameter, error_msg=e):
            self.client._state._negociate_key_share(
                KeyShareResponse(NamedGroup.x25519, b'srv pub'),
                {NamedGroup.x25519: b'cli priv'},
            )
        key_share_resume.assert_called_once_with(NamedGroup.x25519, b'cli priv', b'srv pub')

    @unittest.mock.patch("siotls.states.client.wait_server_hello.key_share_resume")
    def test_negociation_client_key_share_good_key(self, key_share_resume):
        key_share_resume.return_value = (b'shared key', None)
        shared_key = self.client._state._negociate_key_share(
            KeyShareResponse(NamedGroup.x25519, b'srv pub'),
            {NamedGroup.x25519: b'cli priv'},
        )
        key_share_resume.assert_called_once_with(NamedGroup.x25519, b'cli priv', b'srv pub')
        self.assertEqual(shared_key, b'shared key')


class TestNegociationClientMaxFragmentLength(TestNegociationClient):
    def test_negociation_client_max_fragment_length_missing_not_offered(self):
        self.replace_config(max_fragment_length=MaxFragmentLengthOctets.MAX_16384)
        self.client._state._negociate_max_fragment_length(None)
        self.assertEqual(
            self.client.nconfig.max_fragment_length,
            MaxFragmentLengthOctets.MAX_16384,
        )

    def test_negociation_client_max_fragment_length_missing_offered(self):
        self.replace_config(max_fragment_length=MaxFragmentLengthOctets.MAX_1024)
        self.client._state._negociate_max_fragment_length(None)
        self.assertEqual(
            self.client.nconfig.max_fragment_length,
            MaxFragmentLengthOctets.MAX_16384,
        )

    def test_negociation_client_max_fragment_length_present_not_offered(self):
        self.replace_config(max_fragment_length=MaxFragmentLengthOctets.MAX_16384)
        e = "the server-selected max fragment length wasn't offered"
        with self.assertRaises(alerts.IllegalParameter, error_msg=e):
            self.client._state._negociate_max_fragment_length(
                MaxFragmentLength(octets=MaxFragmentLengthOctets.MAX_1024)
            )

    def test_negociation_client_max_fragment_length_present_invalid(self):
        self.replace_config(max_fragment_length=MaxFragmentLengthOctets.MAX_4096)
        e = "the server-selected max fragment length wasn't offered"
        with self.assertRaises(alerts.IllegalParameter, error_msg=e):
            self.client._state._negociate_max_fragment_length(
                MaxFragmentLength(octets=MaxFragmentLengthOctets.MAX_1024)
            )

    def test_negociation_client_max_fragment_length_present_valid(self):
        self.replace_config(max_fragment_length=MaxFragmentLengthOctets.MAX_1024)
        self.client._state._negociate_max_fragment_length(
            MaxFragmentLength(octets=MaxFragmentLengthOctets.MAX_1024)
        )
        self.assertEqual(
            self.client.nconfig.max_fragment_length,
            MaxFragmentLengthOctets.MAX_1024,
        )


class TestNegociationClientALPN(TestNegociationClient):
    def test_negociation_client_alpn_missing_not_offered(self):
        self.replace_config(alpn=[])
        self.client._state._negociate_alpn(None)
        self.assertEqual(self.client.nconfig.alpn, None)

    def test_negociation_client_alpn_missing_offered(self):
        self.replace_config(alpn=['h2', 'http/1.1'])
        self.client._state._negociate_alpn(None)
        self.assertEqual(self.client.nconfig.alpn, None)

    def test_negociation_client_alpn_present_not_offered(self):
        self.replace_config(alpn=[])
        e = "the server-selected application layer protocol (ALPN) wasn't offered"
        with self.assertRaises(alerts.IllegalParameter, error_msg=e):
            self.client._state._negociate_alpn(ALPN(['h2']))

    def test_negociation_client_alpn_present_invalid(self):
        self.replace_config(alpn=['h2', 'http/1.1'])
        e = "the server-selected application layer protocol (ALPN) wasn't offered"
        with self.assertRaises(alerts.IllegalParameter, error_msg=e):
            self.client._state._negociate_alpn(ALPN(['h3']))

    def test_negociation_client_alpn_too_many_protocols_present(self):
        self.replace_config(alpn=['h2', 'http/1.1'])
        e = "the server selected 2 application layer protocols (ALPN) instead of 1"
        with self.assertRaises(alerts.IllegalParameter, error_msg=e):
            self.client._state._negociate_alpn(ALPN(['h2', 'http/1.1']))

    def test_negociation_client_alpn_present_valid(self):
        self.replace_config(alpn=['h2', 'http/1.1'])
        with self.subTest(msg="server picked h2"):
            self.client._state._negociate_alpn(ALPN(['h2']))
            self.assertEqual(self.client.nconfig.alpn, 'h2')
        with self.subTest(msg="server picked h1"):
            self.client._state._negociate_alpn(ALPN(['http/1.1']))
            self.assertEqual(self.client.nconfig.alpn, 'http/1.1')


class TestNegociationClientHeartbeat(TestNegociationClient):
    # Note: we always send the Heartbeat extension

    def test_negociation_client_heartbeat_client_allows_server_pings(self):
        self.replace_config(can_echo_heartbeat=True)
        # We sent PEER_ALLOWED_TO_SEND

        with self.subTest(server_send=False, server_echo=False):
            self.client._state._negociate_heartbeat(None)
            self.assertFalse(self.client.nconfig.can_echo_heartbeat)
            self.assertFalse(self.client.nconfig.can_send_heartbeat)

        with self.subTest(server_send=True, server_echo=False):
            self.client._state._negociate_heartbeat(
                Heartbeat(HeartbeatMode.PEER_NOT_ALLOWED_TO_SEND)
            )
            self.assertTrue(self.client.nconfig.can_echo_heartbeat)
            self.assertFalse(self.client.nconfig.can_send_heartbeat)

        with self.subTest(server_send=True, server_echo=True):
            self.client._state._negociate_heartbeat(
                Heartbeat(HeartbeatMode.PEER_ALLOWED_TO_SEND)
            )
            self.assertTrue(self.client.nconfig.can_echo_heartbeat)
            self.assertTrue(self.client.nconfig.can_send_heartbeat)

    def test_negociation_server_heartbeat_client_refuses_server_pings(self):
        self.replace_config(can_echo_heartbeat=False)
        # We sent PEER_NOT_ALLOWED_TO_SEND

        with self.subTest(server_send=False, server_echo=False):
            self.client._state._negociate_heartbeat(None)
            self.assertFalse(self.client.nconfig.can_echo_heartbeat)
            self.assertFalse(self.client.nconfig.can_send_heartbeat)

        with self.subTest(server_send=True, server_echo=False):
            # server_send negated by PEER_NOT_ALLOWED_TO_SEND
            self.client._state._negociate_heartbeat(None)
            self.assertFalse(self.client.nconfig.can_echo_heartbeat)
            self.assertFalse(self.client.nconfig.can_send_heartbeat)

        with self.subTest(server_send=True, server_echo=True):
            self.client._state._negociate_heartbeat(
                Heartbeat(HeartbeatMode.PEER_ALLOWED_TO_SEND)
            )
            self.assertFalse(self.client.nconfig.can_echo_heartbeat)
            self.assertTrue(self.client.nconfig.can_send_heartbeat)
