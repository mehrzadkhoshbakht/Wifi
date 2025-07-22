import unittest
import sys
import os
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from wifisecpy.modules.wireless_attacker import deauthentication_attack

class TestWirelessAttacker(unittest.TestCase):
    @patch('wifisecpy.modules.wireless_attacker.sendp')
    def test_deauthentication_attack(self, mock_sendp):
        # Call the function
        try:
            deauthentication_attack('00:11:22:33:44:55', '66:77:88:99:AA:BB')
        except KeyboardInterrupt:
            pass

        # Assert that the sendp function was called
        self.assertTrue(mock_sendp.called)

if __name__ == '__main__':
    unittest.main()
