from . import State


class Failed(State):
    can_receive = True  # ignore them
    can_send = False
    can_send_application_data = False

    def process(self, message):
        pass  # ignore all incoming messages
