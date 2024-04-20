from siotls.contents import alerts
from siotls.iana import ContentType, HandshakeType

from .. import State
from . import ServerConnected


class ServerWaitFinished(State):
    can_send_application_data = True

    def __init__(self, connection, server_finished_transcript_hash):
        super().__init__(connection)
        self._server_finished_transcript_hash = server_finished_transcript_hash

    def process(self, finished):
        if finished.content_type != ContentType.HANDSHAKE:
            e = "can only receive Handshake in this state"
            raise alerts.UnexpectedMessage(e)
        if finished.msg_type != HandshakeType.FINISHED:
            e = "can only receive ClientHello in this state"
            raise alerts.UnexpectedMessage(e)

        self._cipher.verify_finish(self._server_finished_transcript_hash, finished.verify_data)
        self._cipher.derive_master_secrets(
            self._server_finished_transcript_hash,
            self._transcript.digest(),
        )

        self._move_to_state(ServerConnected)
