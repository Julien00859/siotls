from ipaddress import ip_address
from itertools import pairwise

from cryptography import x509

from siotls.contents import alerts
from siotls.crypto.ocsp import get_ocsp_url, make_ocsp_request, validate_ocsp
from siotls.iana import (
    CertificateStatusType,
    CertificateType,
    ContentType,
    ExtensionType,
    HandshakeType,
)

from .. import State
from . import ClientWaitCertificateVerify


class ClientWaitCertificate(State):
    can_receive = True
    can_send = True
    can_send_application_data = False

    def __init__(self, connection, must_authentify):
        super().__init__(connection)
        self._must_authentify = must_authentify

    def process(self, content):
        if (content.content_type != ContentType.HANDSHAKE
            or content.msg_type is not HandshakeType.CERTIFICATE):
            super().process(content)
            return

        if self.config.require_peer_authentication:
            if not content.certificate_list:
                e = "missing certificate"
                raise alerts.BadCertificate(e)
        self._check_certificate_types(content.certificate_list)
        match self.nconfig.server_certificate_type:
            case CertificateType.X509:
                self._process_x509(content)
            case CertificateType.RAW_PUBLIC_KEY:
                self._process_raw_public_key(content)
            case _:
                raise NotImplementedError

        self._move_to_state(
            ClientWaitCertificateVerify,
            must_authentify=self._must_authentify,
            certificate_transcript_hash=self._transcript.digest(),
        )

    def _check_certificate_types(self, certificate_entries):
        bad_entries = (
            entry
            for entry in certificate_entries
            if entry.certificate_type != self.nconfig.server_certificate_type
        )
        if bad_entry := next(bad_entries, None):
            e =(f"expected {self.nconfig.server_certificate_type} "
                f"but found {bad_entry.certificate_type}")
            raise alerts.UnsupportedCertificate(e)

    def _process_x509(self, content):
        self.nconfig.peer_certificate = content.certificate_list[0].certificate
        if self.config.require_peer_authentication:
            self._verify_chain(content.certificate_list)
            self._verify_revocation(content.certificate_list)
            self._verify_statuses(content.certificate_list)

    def _verify_chain(self, certificate_entries):
        leaf, *intermediates = (e.certificate for e in certificate_entries)
        try:
            self._get_verifier().verify(leaf, intermediates)
        except x509.verification.VerificationError as exc:
            raise alerts.BadCertificate from exc

    def _get_verifier(self):
        if not self.server_hostname:
            # TODO: implement a a subject-free "build_server_verifier",
            # using "build_client_verifier" is bad because it checks for
            # EKU=Client instead of of EKU=Server... meh.
            return self.config.policy_builder.build_client_verifier()
        try:
            server_ip = ip_address(self.server_hostname)
        except ValueError:
            subject = x509.DNSName(self.server_hostname)
        else:
            subject = x509.IPAddress(server_ip)
        return self.config.policy_builder.build_server_verifier(subject)

    def _verify_revocation(self, certificate_entries):
        if not self.config.revocation_list:
            return
        is_revoked = self.config.revocation_list.get_revoked_certificate_by_serial_number
        for entry in certificate_entries:
            if is_revoked(entry.certificate):
                e = f"{entry.certificate} found in revocation list"
                raise alerts.BadCertificate(e)

    def _verify_statuses(self, certificate_entries):
        for entry, issuer in pairwise(certificate_entries):
            status = entry.extensions.get(ExtensionType.STATUS_REQUEST)
            if status and status.status_type == CertificateStatusType.OCSP:
                ocsp_req = make_ocsp_request(entry.certificate, issuer.certificate)
                ocsp_res = status.ocsp_response
                try:
                    validate_ocsp(issuer.certificate, ocsp_req, ocsp_res)
                except ValueError as exc:
                    raise alerts.BadCertificate from exc
            elif self.ocsp_service and (ocsp_url := get_ocsp_url(entry.certificate)):
                ocsp_req = make_ocsp_request(entry.certificate, issuer.certificate)
                ocsp_res = self.ocsp_service.request(ocsp_url, ocsp_req)
                try:
                    valid_until = validate_ocsp(issuer.certificate, ocsp_req, ocsp_res)
                except ValueError as exc:
                    self.ocsp_service.uncache(ocsp_req)
                    raise alerts.BadCertificate from exc
                else:
                    self.ocsp_service.cache(valid_until, ocsp_req, ocsp_res)

    def _process_raw_public_key(self, content):
        public_key = content.certificate_list[0].public_key
        self.nconfig.peer_public_key = public_key
        if (self.config.require_peer_authentication
            and public_key not in self.config.trusted_public_keys()
        ):
            e = "untrusted raw public key"
            raise alerts.BadCertificate(e)
