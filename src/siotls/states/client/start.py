from .. import State


class ClientStart(State):
    can_send_application_data = False

    def initiate_connection(self):
        ...
