import dataclasses

from siotls.configuration import TLSNegociatedConfiguration
from siotls.contents import ChangeCipherSpec, alerts
from siotls.contents.handshakes import (
    Certificate,
    CertificateRequest,
    CertificateVerify,
    EncryptedExtensions,
    Finished,
    HelloRetryRequest,
    ServerHello,
)
from siotls.contents.handshakes.certificate import (
    X509,
    RawPublicKey,
)
from siotls.contents.handshakes.extensions import (
    ALPN,
    ClientCertificateTypeResponse,
    Heartbeat,
    KeyShareResponse,
    KeyShareRetry,
    OCSPStatus,
    ServerCertificateTypeResponse,
    SignatureAlgorithms,
    SignatureAlgorithmsCert,
    SupportedVersionsResponse,
)
from siotls.crypto.ciphers import TLSCipherSuite
from siotls.crypto.key_share import resume as key_share_resume
from siotls.crypto.ocsp import (
    get_ocsp_url,
    make_ocsp_request,
)
from siotls.crypto.signatures import TLSSignatureSuite
from siotls.iana import (
    CertificateStatusType,
    CertificateType,
    ContentType,
    ExtensionType,
    HandshakeType,
    HeartbeatMode,
    TLSVersion,
)

from .. import State
from . import ServerWaitFinished, ServerWaitFlight2

CERTIFICATE_VERIFY_SERVER = b"".join([
    b" " * 64,
    b"TLS 1.3, server CertificateVerify",
    b"\x00",
])


class ServerWaitClientHello(State):
    can_send_application_data = False

    def __init__(self, connection):
        super().__init__(connection)
        self._is_first_client_hello = True

    def process(self, client_hello):
        self._check(client_hello)
        if self._is_first_client_hello:
            self._setup(client_hello)

        server_extensions, shared_key = self._negociate(client_hello.extensions)
        if not shared_key:
            self._send_hello_retry_request(client_hello.legacy_session_id, server_extensions)
            return
        self._send_server_hello(client_hello.legacy_session_id, server_extensions, shared_key)

        if self.config.require_peer_certificate:
            self._request_user_certificate()

        self._send_server_certificate()

        self._send_finished()

        server_finished_transcript_hash = self._transcript.digest()
        if self.config.require_peer_certificate:
            self._move_to_state(ServerWaitFlight2, server_finished_transcript_hash)
        else:
            self._move_to_state(ServerWaitFinished, server_finished_transcript_hash)

    def _check(self, client_hello):
        if client_hello.content_type != ContentType.HANDSHAKE:
            e = "can only receive Handshake in this state"
            raise alerts.UnexpectedMessage(e)
        if client_hello.msg_type != HandshakeType.CLIENT_HELLO:
            e = "can only receive ClientHello in this state"
            raise alerts.UnexpectedMessage(e)
        if not self._is_first_client_hello:
            cipher_suite = self._find_common_cipher_suite(client_hello.cipher_suites)
            if client_hello.random != self._client_unique:
                e = "client's random cannot change in between Hellos"
                raise alerts.IllegalParameter(e)

    def _setup(self, client_hello):
        cipher_suite = self._find_common_cipher_suite(client_hello.cipher_suites)
        self.nconfig = TLSNegociatedConfiguration(cipher_suite)
        self._client_unique = client_hello.random
        self._cipher = TLSCipherSuite[cipher_suite](
            'server', self._client_unique, log_keys=self.config.log_keys)
        self._transcript.post_init(self._cipher.digestmod)

    def _find_common_cipher_suite(self, cipher_suites):
        for cipher_suite in self.config.cipher_suites:
            if cipher_suite in cipher_suites:
                return cipher_suite
        e = "no common cipher suite found"
        raise alerts.HandshakeFailure(e)

    def _send_hello_retry_request(self, session_id, server_extensions):
        if not self._is_first_client_hello:
            e = "invalid KeyShare in second ClientHello"
            raise alerts.IllegalParameter(e)
        self._is_first_client_hello = False

        # make sure the client doesn't change its algorithms in between flights
        self.config = dataclasses.replace(self.config,
            cipher_suites=[self._cipher.iana_id],
            key_exchanges=[self.nconfig.key_exchange],
            signature_algorithms=[self._signature.iana_id]
        )

        clear_extensions, _ = server_extensions
        self._send_content(HelloRetryRequest(
            HelloRetryRequest.random,
            session_id,
            self._cipher.iana_id,
            clear_extensions,
        ))
        self._transcript.do_hrr_dance()
        self._send_content(ChangeCipherSpec())

    def _send_server_hello(self, session_id, extensions, shared_key):
        clear_extensions, encrypted_extensions = extensions

        self._cipher.skip_early_secrets()
        self._send_content(ServerHello(
            self._server_unique,
            session_id,
            self._cipher.iana_id,
            clear_extensions,
        ))
        if self._is_first_client_hello:
            self._send_content(ChangeCipherSpec())
        self._cipher.derive_handshake_secrets(shared_key, self._transcript.digest())
        self._send_content(EncryptedExtensions(encrypted_extensions))

    def _request_user_certificate(self):
        # we ignore POST_HANDSHAKE_AUTH at the moment
        certificate_request_extensions = [
            SignatureAlgorithms(self.config.signature_algorithms),
        ]
        self._send_content(CertificateRequest(
            certificate_request_context=b'',  # only for POST_HANDSHAKE_AUTH
            extensions=certificate_request_extensions,
        ))

    def _send_server_certificate(self):
        certificate_list = []
        if self.nconfig.server_certificate_type == CertificateType.RAW_PUBLIC_KEY:
            certificate_list.append(RawPublicKey(self.config.public_key, []))
        else:  # x509
            certificate_list.extend([
                X509(certificate, [])
                for certificate
                in self.config.certificate_chain
            ])

            if (
                self.nconfig.peer_want_ocsp_stapling
                and self.ocsp_callback
                and len(self.config.certificate_chain) > 1
            ):
                ocsp_url = get_ocsp_url(self.config.certificate_chain[0])
                ocsp_req = make_ocsp_request(
                    self.config.certificate_chain[0],
                    self.config.certificate_chain[1],
                )
                ocsp_res = self.ocsp_service(ocsp_url, ocsp_req)
                certificate_list[0].extensions.append(OCSPStatus(ocsp_res))

        self._send_content(Certificate(b'', certificate_list))
        self._send_content(CertificateVerify(
            self._signature.iana_id,
            self._signature.sign(b''.join([
                CERTIFICATE_VERIFY_SERVER,
                self._transcript.digest(),
            ]))
        ))

    def _send_finished(self):
        ...

    def _negociate(self, client_extensions):
        clear_extensions = []
        encrypted_extensions = []

        def negociate(ext_name, *args, **kwargs):
            ext_type = getattr(ExtensionType, ext_name.upper())
            ext = client_extensions.get(ext_type)
            meth = getattr(self, f'_negociate_{ext_name}')
            clear_exts, encrypted_exts, *rest = meth(ext, *args, **kwargs)
            clear_extensions.extend(clear_exts)
            encrypted_extensions.extend(encrypted_exts)
            return rest[0] if rest else None

        negociate('supported_versions')
        negociate('supported_groups')
        negociate('signature_algorithms')

        shared_key = negociate('key_share')
        if not shared_key:
            return (clear_extensions, encrypted_extensions), None

        negociate('client_certificate_type')
        negociate('server_certificate_type')

        negociate('max_fragment_length')
        negociate('application_layer_protocol_negotiation')
        negociate('heartbeat')
        negociate('status_request')

        return (clear_extensions, encrypted_extensions), shared_key

    def _negociate_supported_versions(self, supported_versions_ext):
        if not supported_versions_ext:
            e = "client doesn't support TLS 1.3"
            raise alerts.ProtocolVersion(e)
        if TLSVersion.TLS_1_3 not in supported_versions_ext.versions:
            e = "client doesn't support TLS 1.3"
            raise alerts.ProtocolVersion(e)
        return [SupportedVersionsResponse(TLSVersion.TLS_1_3)], []

    def _negociate_supported_groups(self, supported_groups_ext):
        if not supported_groups_ext:
            raise alerts.MissingExtension(ExtensionType.SUPPORTED_GROUPS)
        for group in self.config.key_exchanges:
            if group in supported_groups_ext.named_group_list:
                self.nconfig.key_exchange = group
                return [], []
        e = "no common key exchange found"
        raise alerts.HandshakeFailure(e)

    def _negociate_client_certificate_type(self, cct_ext):
        if not self.config.require_peer_certificate:
            return [], []
        client_cert_types = cct_ext.certificate_types if cct_ext else [CertificateType.X509]
        for cert_type in self.config.peer_certificate_types:
            if cert_type in client_cert_types:
                self.nconfig.client_certificate_type = cert_type
                if cct_ext:
                    return [], [ClientCertificateTypeResponse(cert_type)]
                return [], []
        e = "no common client certificate type found"
        raise alerts.UnsupportedCertificate(e)

    def _negociate_server_certificate_type(self, sct_ext):
        server_cert_types = sct_ext.certificate_types if sct_ext else [CertificateType.X509]
        for cert_type in self.config.certificate_types:
            if cert_type in server_cert_types:
                self.nconfig.server_certificate_type = cert_type
                if sct_ext:
                    return [], [ServerCertificateTypeResponse(cert_type)]
                return [], []
        e = "no common server certificate type found"
        raise alerts.UnsupportedCertificate(e)

    def _negociate_signature_algorithms(self, sa_ext):
        if not sa_ext:
            raise alerts.MissingExtension(ExtensionType.SIGNATURE_ALGORITHMS)
        suites = TLSSignatureSuite.for_certificate(self.config.certificate_chain[0])
        for server_suite in self.config.signature_algorithms:
            if server_suite in suites and server_suite in sa_ext.supported_signature_algorithms:
                self._signature = suites[server_suite](self.config.private_key)
                return [], []
        e = "no common signature algorithm found"
        raise alerts.HandshakeFailure(e)

    def _negociate_key_share(self, key_share_ext):
        key_exchange = self.nconfig.key_exchange
        if key_share_ext and key_exchange in key_share_ext.client_shares:
            # possible to resume key share => ServerHello
            peer_exchange = key_share_ext.client_shares[key_exchange]
            try:
                shared_key, my_exchange = key_share_resume(
                    key_exchange, None, peer_exchange)
            except ValueError as exc:
                e = "error while resuming key share"
                raise alerts.HandshakeFailure(e) from exc
            response = KeyShareResponse(key_exchange, my_exchange)
        else:
            # impossible to resume key share => HelloRetryRequest
            shared_key = None
            response = KeyShareRetry(key_exchange)
        return [response], [], shared_key

    def _negociate_max_fragment_length(self, mfl_ext):
        if mfl_ext:
            self.nconfig.max_fragment_length = mfl_ext.octets
            return [], [mfl_ext]

        self.nconfig.max_fragment_length = self.config.max_fragment_length
        return [], []

    def _negociate_application_layer_protocol_negotiation(self, alpn_ext):
        if not alpn_ext or not self.config.alpn:
            self.nconfig.alpn = None
            return [], []
        for proto in self.config.alpn:
            if proto in alpn_ext.protocol_name_list:
                self.nconfig.alpn = proto
                return [], [ALPN([proto])]
        e = "no common application layer protocol found"
        raise alerts.NoApplicationProtocol(e)
    _negociate_alpn = _negociate_application_layer_protocol_negotiation

    def _negociate_heartbeat(self, client_hb):
        if not client_hb:
            self.nconfig.can_send_heartbeat = False
            self.nconfig.can_echo_heartbeat = False
            return [], []

        self.nconfig.can_send_heartbeat = (
            client_hb.mode == HeartbeatMode.PEER_ALLOWED_TO_SEND
        )
        self.nconfig.can_echo_heartbeat = self.config.can_echo_heartbeat
        response = Heartbeat(
            HeartbeatMode.PEER_ALLOWED_TO_SEND
            if self.config.can_echo_heartbeat else
            HeartbeatMode.PEER_NOT_ALLOWED_TO_SEND
        )
        return [], [response]

    def _negociate_status_request(self, status_request_ext):
        if not status_request_ext:
            self.nconfig.peer_want_ocsp_stapling = False
        else:
            self.nconfig.peer_want_ocsp_stapling = (
                status_request_ext.status_type == CertificateStatusType.OCSP
            )
        return [], []
