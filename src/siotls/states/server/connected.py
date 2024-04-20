from .. import State


class ServerConnected(State):
    can_send_application_data = True

    def process(self, message):
        pass
