from .. import State
from . import ServerWaitClientHello


class ServerStart(State):
    can_receive = True
    can_send = True
    can_send_application_data = False

    def initiate_connection(self):
        self._move_to_state(ServerWaitClientHello)

    def process(self, message):
        super().process(message)
