import abc
import logging

from siotls.contents.alerts import Alert, UnexpectedMessage
from siotls.iana import AlertDescription, AlertLevel, ContentType

logger = logging.getLogger('siotls.connection')


class State(metaclass=abc.ABCMeta):
    can_recveive: bool
    can_send: bool
    can_send_application_data: bool

    def __init__(self, connection):
        super().__setattr__('connection', connection)

    def __getattr__(self, name):
        return getattr(self.connection, name)

    def __setattr__(self, name, value):
        if hasattr(self.connection, name):
            setattr(self.connection, name, value)
        super().__setattr__(name, value)

    @classmethod
    def name(cls):
        return cls.__name__

    def initiate_connection(self):
        e = f"cannot initiate connection in state {self.name()}"
        raise NotImplementedError(e)

    @abc.abstractmethod
    def process(self, content):
        if content.content_type == ContentType.ALERT:
            alert = content
            if alert.description == AlertDescription.CLOSE_NOTIFY:
                self._move_to_state(Closed)
                self._state.can_receive = False
                logger.debug("%s closed its sending side", self.config.other_side)
            elif alert.level == AlertLevel.WARNING:
                logger.debug("warning alert from %s: %s",
                     self.config.other_side, content.description.name)
            else:
                e = f"fatal alert from {self.config.other_side}"
                raise Alert[alert.description](e)
        elif content.content_type == ContentType.HEARTBEAT:
            raise NotImplementedError
        else:
            e =(f"cannot process {type(content).__name__} in state "
                f"{self.name()}")
            raise UnexpectedMessage(e)

# isort: off
from .closed import Closed
from .connected import Connected
from .failed import Failed
from .client import (
    ClientStart,
    ClientWaitCertCr,
    ClientWaitCertificate,
    ClientWaitCertificateVerify,
    ClientWaitEncryptedExtensions,
    ClientWaitFinished,
    ClientWaitServerHello,
)
from .server import (
    ServerStart,
    ServerWaitCertificate,
    ServerWaitCertificateVerify,
    ServerWaitClientHello,
    ServerWaitEndOfEarlyData,
    ServerWaitFinished,
    ServerWaitFlight2,
)
