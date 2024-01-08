import unittest
from siotls.contents.handshakes import Handshake, EncryptedExtensions
from siotls.contents.handshakes.extensions import ServerNameList, HostName
from siotls.serial import SerialIO


class TestEncryptedExtensions(unittest.TestCase):

    def test_encryted_extensions01(self):
        data = bytes.fromhex("00120000000e000c0000096c6f63616c686f7374")
        stream = SerialIO(data)
        ee = EncryptedExtensions.parse_body(stream)
        self.assertTrue(stream.is_eof())
        self.assertEqual(ee, EncryptedExtensions([
            ServerNameList([HostName('localhost')]),
        ]))
        self.assertEqual(ee.serialize_body(), data)
