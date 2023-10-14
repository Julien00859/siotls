from .. import State


class ClientWaitFinished(State):
    can_send_application_data = False
