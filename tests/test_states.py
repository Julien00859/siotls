import dataclasses

from siotls import TLSConnection
from siotls.contents import ApplicationData
from siotls.contents.alerts import HandshakeFailure, IllegalParameter, UnexpectedMessage
from siotls.contents.handshakes import ClientHello, Finished, HelloRetryRequest
from siotls.contents.handshakes.extensions import (
    KeyShareRetry,
    SignatureAlgorithms,
    SupportedGroups,
    SupportedVersionsRequest,
    SupportedVersionsResponse,
)
from siotls.iana import TLSVersion

from . import TestCase, tls_decode
from .config import client_config, server_config


class TestStateServerWaitClientHello(TestCase):
    def test_state_server_wait_client_hello_bad_content_type(self):
        server_conn = TLSConnection(server_config)
        server_conn.initiate_connection()

        e = "cannot process ApplicationData in state ServerWaitClientHello"
        with self.assertRaises(UnexpectedMessage, error_msg=e):
            server_conn._state.process(ApplicationData(b""))

    def test_state_server_wait_client_hello_bad_msg_type(self):
        server_conn = TLSConnection(server_config)
        server_conn.initiate_connection()

        e = "cannot process Finished in state ServerWaitClientHello"
        with self.assertRaises(UnexpectedMessage, error_msg=e):
            server_conn._state.process(Finished(b""))

    def test_state_server_wait_client_hello_hrr_cipher_changed(self):
        server_conn = TLSConnection(server_config)
        server_conn.initiate_connection()

        cipher_suites_first_flight = [client_config.cipher_suites[0]]
        cipher_suites_second_flight = [client_config.cipher_suites[1]]

        # first flight
        client_conn = TLSConnection(dataclasses.replace(client_config,
            cipher_suites=cipher_suites_first_flight,
        ))
        client_conn._send_content(ClientHello(
            random=client_conn._client_unique,
            cipher_suites=cipher_suites_first_flight,
            extensions=[
                SupportedVersionsRequest([TLSVersion.TLS_1_3]),
                SignatureAlgorithms(client_conn.config.signature_algorithms),
                SupportedGroups(client_conn.config.key_exchanges),
            ]
        ))
        client_hello_first_flight = client_conn.data_to_send()
        server_conn.receive_data(client_hello_first_flight)
        self.assertEqual(
            tls_decode(client_conn, server_conn.data_to_send()),
            [HelloRetryRequest(
                random=HelloRetryRequest.random,
                legacy_session_id_echo=b"",
                cipher_suite=cipher_suites_first_flight[0],
                extensions=[
                    SupportedVersionsResponse(TLSVersion.TLS_1_3),
                    KeyShareRetry(server_config.key_exchanges[0])
                ],
            )]
        )

        # second flight
        # use a new connection to not tamper with the transcript
        client_conn = TLSConnection(dataclasses.replace(client_config,
            cipher_suites=cipher_suites_second_flight,
        ))
        client_conn._send_content(ClientHello(
            random=client_conn._client_unique,
            cipher_suites=cipher_suites_second_flight,
            extensions=[
                SupportedVersionsRequest([TLSVersion.TLS_1_3]),
                SignatureAlgorithms(client_conn.config.signature_algorithms),
                SupportedGroups(client_conn.config.key_exchanges),
            ]
        ))
        client_hello_second_flight = client_conn.data_to_send()

        e = "no common cipher suite found"
        with self.assertRaises(HandshakeFailure, error_msg=e):
            server_conn.receive_data(client_hello_second_flight)
        self.assertEqual(
            tls_decode(client_conn, server_conn.data_to_send()),
            [HandshakeFailure()]
        )

    def test_state_server_wait_client_hello_hrr_client_unique_changed(self):
        server_conn = TLSConnection(server_config)
        server_conn.initiate_connection()

        client_unique_first_flight = b"a" * 32
        client_unique_second_flight = b"b" * 32

        # first flight
        client_conn = TLSConnection(client_config)
        client_conn._send_content(ClientHello(
            random=client_unique_first_flight,
            cipher_suites=client_conn.config.cipher_suites,
            extensions=[
                SupportedVersionsRequest([TLSVersion.TLS_1_3]),
                SignatureAlgorithms(client_conn.config.signature_algorithms),
                SupportedGroups(client_conn.config.key_exchanges),
            ]
        ))
        client_hello_first_flight = client_conn.data_to_send()
        server_conn.receive_data(client_hello_first_flight)
        self.assertEqual(
            tls_decode(client_conn, server_conn.data_to_send()),
            [HelloRetryRequest(
                random=HelloRetryRequest.random,
                legacy_session_id_echo=b"",
                cipher_suite=server_conn.config.cipher_suites[0],
                extensions=[
                    SupportedVersionsResponse(TLSVersion.TLS_1_3),
                    KeyShareRetry(server_config.key_exchanges[0])
                ],
            )]
        )

        # second flight
        # use a new connection to not tamper with the transcript
        client_conn = TLSConnection(client_config)
        client_conn._send_content(ClientHello(
            random=client_unique_second_flight,
            cipher_suites=client_conn.config.cipher_suites,
            extensions=[
                SupportedVersionsRequest([TLSVersion.TLS_1_3]),
                SignatureAlgorithms(client_conn.config.signature_algorithms),
                SupportedGroups(client_conn.config.key_exchanges),
            ]
        ))
        client_hello_second_flight = client_conn.data_to_send()

        e = "client's random cannot change in between Hellos"
        with self.assertRaises(IllegalParameter, error_msg=e):
            server_conn.receive_data(client_hello_second_flight)
        self.assertEqual(
            tls_decode(client_conn, server_conn.data_to_send()),
            [IllegalParameter()]
        )
