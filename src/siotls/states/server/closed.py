from .. import State


class ServerClosed(State):
    can_send_application_data = True
