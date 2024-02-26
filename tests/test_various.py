from siotls.contents.handshakes.extensions import Extension
from siotls.iana import (
    ExtensionType,
    HandshakeType,
)

from . import TestCase


class TestVarious(TestCase):
    def test_various_extension_registry(self):
        e =(r"cannot register <class '.*\.<locals>\.FakeCookie'> at "
            r"pair \(COOKIE, CLIENT_HELLO\), another exist already: "
            r"<class 'siotls\..*\.Cookie'>")
        with self.assertRaisesRegex(ValueError, e):
            class FakeCookie(Extension):
                extension_type = ExtensionType.COOKIE
                _handshake_types = (HandshakeType.CLIENT_HELLO,)
