from .. import State


class ClientClosed(State):
    can_send_application_data = False
