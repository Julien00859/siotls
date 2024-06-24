from siotls.contents import alerts
from siotls.contents.handshakes import Finished
from siotls.iana import ContentType, HandshakeType

from .. import Connected, State


class ClientWaitFinished(State):
    can_receive = True
    can_send = True
    can_send_application_data = False

    def __init__(self, connection, must_authentify, certificate_verify_transcript_hash):
        super().__init__(connection)
        self._must_authentify = must_authentify
        self._certificate_verify_transcript_hash = certificate_verify_transcript_hash

    def process(self, content):
        if (content.content_type != ContentType.HANDSHAKE
            or content.msg_type is not HandshakeType.FINISHED):
            super().process(content)
            return

        try:
            self._cipher.verify_finish(
                self._certificate_verify_transcript_hash,
                content.verify_data
            )
        except ValueError as exc:
            raise alerts.DecryptError from exc
        server_finished_transcript_hash = self._transcript.digest()

        if self._must_authentify:
            self._send_certificate()

        self._send_content(Finished(
            self._cipher.sign_finish(self._transcript.digest())
        ))

        client_finished_transcript_hash = self._transcript.digest()
        self._cipher.derive_master_secrets(
            server_finished_transcript_hash,
            client_finished_transcript_hash,
        )

        self._move_to_state(Connected)

    def _send_certificate(self):
        raise NotImplementedError
