import unittest
import sys
import os
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from wifisecpy.modules.port_scanner import scan_ports

class TestPortScanner(unittest.TestCase):
    @patch('socket.socket')
    def test_scan_ports_success(self, mock_socket):
        # Mock the socket to return a successful result
        mock_socket_instance = MagicMock()
        mock_socket_instance.connect_ex.return_value = 0
        mock_socket.return_value.__enter__.return_value = mock_socket_instance

        # Call the function
        open_ports = scan_ports('127.0.0.1', [80, 443])

        # Assert that the function returns the expected result
        self.assertEqual(len(open_ports), 2)
        self.assertIn(80, open_ports)
        self.assertIn(443, open_ports)

    @patch('socket.socket')
    def test_scan_ports_socket_error(self, mock_socket):
        # Mock the socket to raise a socket.error
        mock_socket.side_effect = Exception

        # Call the function
        open_ports = scan_ports('127.0.0.1', [80, 443])

        # Assert that the function returns an empty list
        self.assertEqual(len(open_ports), 0)

if __name__ == '__main__':
    unittest.main()
