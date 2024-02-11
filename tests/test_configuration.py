import logging

from siotls import TLSConfiguration, TLSConnection
from siotls.iana import MaxFragmentLengthOctets

from . import TestCase


class TestConfiguration(TestCase):
    def test_config_max_fragment_length(self):
        config = TLSConfiguration(
            'server',
            max_fragment_length=MaxFragmentLengthOctets.MAX_512
        )
        e = "max fragment length is only configurable client side"
        with self.assertRaises(ValueError, error_msg=e):
            config.validate()

    def test_config_log_keys_info(self):
        config = TLSConfiguration('server')
        conn = TLSConnection(config, log_keys=True)

        m = "Key log enabled for current connection."
        with self.assertLogs('siotls.keylog', logging.DEBUG), \
             self.assertLogs('siotls.connection', logging.INFO, log_msg=m):
            logging.getLogger('siotls.keylog').debug('test_config_log_keys')
            conn.initiate_connection()

    def test_config_log_keys_warning(self):
        config = TLSConfiguration('server')
        conn = TLSConnection(config, log_keys=True)

        m =("Key log was requested for current connection but no "
            "logging.Handler seems setup on the 'siotls.keylog' logger. "
            "You must setup one.\nlogging.getLogger('siotls.keylog')."
            "addHandler(logging.FileHandler(path_to_keylogfile, 'w'))")
        with self.assertLogs('siotls.connection', logging.WARNING, log_msg=m):
            conn.initiate_connection()
