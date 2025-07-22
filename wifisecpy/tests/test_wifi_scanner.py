import unittest
import sys
import os
from unittest.mock import patch, Mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from wifisecpy.modules.wifi_scanner import scan_wifi_networks

class TestWifiScanner(unittest.TestCase):
    @patch('subprocess.run')
    def test_scan_wifi_networks_success(self, mock_subprocess_run):
        # Mock the subprocess.run to return a successful result
        mock_process = Mock()
        mock_process.stdout = '[{"ssid": "Test Network", "bssid": "00:11:22:33:44:55", "rssi": -50, "capabilities": "WPA2"}]'
        mock_subprocess_run.return_value = mock_process

        # Call the function
        networks = scan_wifi_networks()

        # Assert that the function returns the expected result
        self.assertEqual(len(networks), 1)
        self.assertEqual(networks[0]['ssid'], 'Test Network')

    @patch('subprocess.run')
    def test_scan_wifi_networks_file_not_found(self, mock_subprocess_run):
        # Mock the subprocess.run to raise a FileNotFoundError
        mock_subprocess_run.side_effect = FileNotFoundError

        # Call the function
        networks = scan_wifi_networks()

        # Assert that the function returns None
        self.assertIsNone(networks)

    @patch('subprocess.run')
    def test_scan_wifi_networks_called_process_error(self, mock_subprocess_run):
        # Mock the subprocess.run to raise a CalledProcessError
        mock_subprocess_run.side_effect = subprocess.CalledProcessError(1, 'cmd')

        # Call the function
        networks = scan_wifi_networks()

        # Assert that the function returns None
        self.assertIsNone(networks)

    @patch('subprocess.run')
    def test_scan_wifi_networks_json_decode_error(self, mock_subprocess_run):
        # Mock the subprocess.run to return invalid JSON
        mock_process = Mock()
        mock_process.stdout = 'invalid json'
        mock_subprocess_run.return_value = mock_process

        # Call the function
        networks = scan_wifi_networks()

        # Assert that the function returns None
        self.assertIsNone(networks)

if __name__ == '__main__':
    unittest.main()
