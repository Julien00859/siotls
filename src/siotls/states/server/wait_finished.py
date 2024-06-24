from siotls.contents import alerts
from siotls.iana import ContentType, HandshakeType

from .. import Connected, State


class ServerWaitFinished(State):
    can_receive = True
    can_send = True
    can_send_application_data = True

    def __init__(self, connection, server_finished_transcript_hash):
        super().__init__(connection)
        self._server_finished_transcript_hash = server_finished_transcript_hash

    def process(self, finished):
        if (finished.content_type != ContentType.HANDSHAKE
            or finished.msg_type != HandshakeType.FINISHED):
            super().process(finished)
            return

        try:
            self._cipher.verify_finish(
                self._server_finished_transcript_hash,
                finished.verify_data
            )
        except ValueError as exc:
            raise alerts.DecryptError from exc

        self._cipher.derive_master_secrets(
            self._server_finished_transcript_hash,
            self._transcript.digest(),
        )

        self._move_to_state(Connected)
