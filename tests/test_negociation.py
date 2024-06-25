import collections
import dataclasses

from parameterized import parameterized

from siotls.configuration import TLSNegotiatedConfiguration
from siotls.connection import TLSConnection
from siotls.contents import alerts
from siotls.contents.handshakes.extensions import (
    ALPN,
    ClientCertificateTypeRequest,
    ClientCertificateTypeResponse,
    Heartbeat,
    KeyShareRequest,
    KeyShareResponse,
    KeyShareRetry,
    MaxFragmentLength,
    ServerCertificateTypeRequest,
    ServerCertificateTypeResponse,
    SupportedGroups,
    SupportedVersionsRequest,
    SupportedVersionsResponse,
)
from siotls.crypto import TLSKeyExchange
from siotls.iana import (
    CertificateType,
    CipherSuites,
    ExtensionType,
    HeartbeatMode,
    MaxFragmentLengthOctets,
    NamedGroup,
    TLSVersion,
)
from siotls.states import (
    ClientWaitEncryptedExtensions,
    ClientWaitServerHello,
    ServerWaitClientHello,
)

from . import TestCase
from .config import (
    ca_cert,
    client_config,
    server_cert,
    server_config,
    server_pubkey,
    test_trust_store,
    test_trusted_public_keys,
)

# ----------------------------------------------------------------------
# Server-side, upon receiving ClientHello
# ----------------------------------------------------------------------

class TestNegociationServer(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = TLSConnection(server_config)
        cls.server._state = ServerWaitClientHello(cls.server)

    def setUp(self):
        self.server.nconfig = TLSNegotiatedConfiguration()

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
        with self.assertRaises(alerts.MissingExtension) as capture:
            self.server._state._negociate_supported_groups(None)
        self.assertEqual(capture.exception.args, (ExtensionType.SUPPORTED_GROUPS,))

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


class TestNegociationServerClientCertificateType(TestNegociationServer):
    Case = collections.namedtuple("Case", (
        'trust_store', 'trusted_pubkey', 'user_types', 'type_', 'response'))
    CT_X509 = CertificateType.X509
    CT_RPK = CertificateType.RAW_PUBLIC_KEY
    ALERT_UC = alerts.UnsupportedCertificate

    @parameterized.expand([
        # trust  trusted
        # store, pubkey, user types,          type,     response
        ( False, False,  None,                None,     False),
        ( False, False,  [CT_X509],           None,     False),
        ( False, False,  [CT_RPK],            None,     False),
        ( False, False,  [CT_X509, CT_RPK],   None,     False),
        ( False, False,  [CT_RPK, CT_X509],   None,     False),

        ( True,  False,  None,                CT_X509,  False),
        ( True,  False,  [CT_X509],           CT_X509,  True),
        ( True,  False,  [CT_RPK],            ALERT_UC, False),
        ( True,  False,  [CT_X509, CT_RPK],   CT_X509,  True),
        ( True,  False,  [CT_RPK, CT_X509],   CT_X509,  True),

        ( False, True,   None,                ALERT_UC, False),
        ( False, True,   [CT_X509],           ALERT_UC, False),
        ( False, True,   [CT_RPK],            CT_RPK,   True),
        ( False, True,   [CT_X509, CT_RPK],   CT_RPK,   True),
        ( False, True,   [CT_RPK, CT_X509],   CT_RPK,   True),

        ( True,  True,   None,                CT_X509,  False),
        ( True,  True,   [CT_X509],           CT_X509,  True),
        ( True,  True,   [CT_RPK],            CT_RPK,   True),
        ( True,  True,   [CT_X509, CT_RPK],   CT_X509,  True),
        ( True,  True,   [CT_RPK, CT_X509],   CT_X509,  True),
    ])
    def test_negociation_server_client_certificate_type(  # noqa: PLR0913
        self, trust_store, trusted_pubkey, user_types, type_, response,
    ):
        self.replace_config(
            trust_store=test_trust_store if trust_store else None,
            trusted_public_keys=test_trusted_public_keys if trusted_pubkey else None,
        )
        ext = None if user_types is None else ClientCertificateTypeRequest(user_types)

        if type_ == alerts.UnsupportedCertificate:
            with self.assertRaises(alerts.UnsupportedCertificate):
                self.server._state._negociate_client_certificate_type(ext)
        else:
            clears, crypts = self.server._state._negociate_client_certificate_type(ext)
            self.assertEqual(clears, [])
            self.assertEqual(crypts, [ClientCertificateTypeResponse(type_)] if response else [])
            self.assertEqual(self.server.nconfig.client_certificate_type, type_)


class TestNegociationServerServerCertificateType(TestNegociationServer):
    Case = collections.namedtuple("Case", (
        'cert', 'pubkey', 'user_types', 'type_', 'response'))
    CT_X509 = CertificateType.X509
    CT_RPK = CertificateType.RAW_PUBLIC_KEY
    ALERT_UC = alerts.UnsupportedCertificate

    @parameterized.expand([
        # cert,  pubkey, user types,          type,     response
        ( True,  False,  None,                CT_X509,  False),
        ( True,  False,  [CT_X509],           CT_X509,  True),
        ( True,  False,  [CT_RPK],            ALERT_UC, False),
        ( True,  False,  [CT_X509, CT_RPK],   CT_X509,  True),

        ( False, True,   None,                ALERT_UC, False),
        ( False, True,   [CT_X509],           ALERT_UC, False),
        ( False, True,   [CT_RPK],            CT_RPK,   True),
        ( False, True,   [CT_X509, CT_RPK],   CT_RPK,   True),

        ( True,  True,   None,                CT_X509,  False),
        ( True,  True,   [CT_X509],           CT_X509,  True),
        ( True,  True,   [CT_RPK],            CT_RPK,   True),
        ( True,  True,   [CT_X509, CT_RPK],   CT_X509,  True),
    ])
    def test_negociation_server_server_certificate_type(  # noqa: PLR0913
        self, cert, pubkey, user_types, type_, response,
    ):
        self.replace_config(
            certificate_chain=[server_cert, ca_cert] if cert else None,
            public_key=server_pubkey if pubkey else None,
        )
        ext = None if user_types is None else ServerCertificateTypeRequest(user_types)

        if type_ == alerts.UnsupportedCertificate:
            with self.assertRaises(alerts.UnsupportedCertificate):
                self.server._state._negociate_server_certificate_type(ext)
        else:
            clears, crypts = self.server._state._negociate_server_certificate_type(ext)
            self.assertEqual(clears, [])
            self.assertEqual(crypts, [ServerCertificateTypeResponse(type_)] if response else [])
            self.assertEqual(self.server.nconfig.server_certificate_type, type_)


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

    def test_negociation_server_key_share_good(self):
        self.server.nconfig.key_exchange = NamedGroup.x25519
        client_pk, client_share = TLSKeyExchange[NamedGroup.x25519].init()
        clears, crypts, shared_key1 = self.server._state._negociate_key_share(
            KeyShareRequest({NamedGroup.x25519: client_share})
        )
        self.assertEqual([type(ext) for ext in clears], [KeyShareResponse])
        self.assertEqual(clears[0].group, NamedGroup.x25519)

        server_exchange = clears[0].key_exchange
        shared_key2 = TLSKeyExchange[NamedGroup.x25519].resume(client_pk, server_exchange)
        self.assertEqual(shared_key1, shared_key2)

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
        cls.client = TLSConnection(client_config)
        if cls.state_name == 'server hello':
            cls.client._state = ClientWaitServerHello(cls.client, {}, b"")
        elif cls.state_name == 'encrypted extension':
            cls.client._state = ClientWaitEncryptedExtensions(cls.client)
        else:
            raise ValueError(cls.client._state)

    def setUp(self):
        self.client.nconfig = TLSNegotiatedConfiguration()

    @classmethod
    def replace_config(cls, **kwargs):
        cls.client.config = dataclasses.replace(cls.client.config, **kwargs)


class TestNegociationClientSupportedVersions(TestNegociationClient):
    state_name = 'server hello'

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
    state_name = 'server hello'

    def test_negociation_client_key_share_missing(self):
        we_dont_care = None  # used as placeholder
        with self.assertRaises(alerts.MissingExtension) as capture:
            self.client._state._negociate_key_share(None, {
                NamedGroup.x25519: we_dont_care
            })
        self.assertEqual(capture.exception.args, (ExtensionType.KEY_SHARE,))

    def test_negociation_client_key_share_not_offered(self):
        we_dont_care = None  # used as placeholder
        e = "the server-selected key exchange wasn't offered"
        with self.assertRaises(alerts.IllegalParameter, error_msg=e):
            self.client._state._negociate_key_share(
                KeyShareResponse(NamedGroup.x448, we_dont_care),
                {NamedGroup.x25519: we_dont_care},
            )

class TestNegociationClientMaxFragmentLength(TestNegociationClient):
    state_name = 'encrypted extension'

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
    state_name = 'encrypted extension'

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
    state_name = 'encrypted extension'
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
