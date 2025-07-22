import unittest
import sys
import os
from unittest.mock import patch, Mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from wifisecpy.modules.device_discoverer import discover_devices, get_mac_vendor

class TestDeviceDiscoverer(unittest.TestCase):
    @patch('wifisecpy.modules.device_discoverer.srp')
    @patch('wifisecpy.modules.device_discoverer.get_mac_vendor')
    def test_discover_devices_success(self, mock_get_mac_vendor, mock_srp):
        # Mock the srp to return a successful result
        mock_received = Mock()
        mock_received.psrc = '192.168.1.1'
        mock_received.hwsrc = '00:11:22:33:44:55'
        mock_srp.return_value = [([None, mock_received], [None, mock_received])]

        # Mock the get_mac_vendor to return a successful result
        mock_get_mac_vendor.return_value = 'Test Vendor'

        # Call the function
        devices = discover_devices('192.168.1.0/24')

        # Assert that the function returns the expected result
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]['ip'], '192.168.1.1')
        self.assertEqual(devices[0]['mac'], '00:11:22:33:44:55')
        self.assertEqual(devices[0]['vendor'], 'Test Vendor')

    @patch('requests.get')
    def test_get_mac_vendor_success(self, mock_requests_get):
        # Mock the requests.get to return a successful result
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = 'Test Vendor'
        mock_requests_get.return_value = mock_response

        # Call the function
        vendor = get_mac_vendor('00:11:22:33:44:55')

        # Assert that the function returns the expected result
        self.assertEqual(vendor, 'Test Vendor')

    @patch('requests.get')
    def test_get_mac_vendor_not_found(self, mock_requests_get):
        # Mock the requests.get to return a 404 status code
        mock_response = Mock()
        mock_response.status_code = 404
        mock_requests_get.return_value = mock_response

        # Call the function
        vendor = get_mac_vendor('00:11:22:33:44:55')

        # Assert that the function returns None
        self.assertIsNone(vendor)

    @patch('requests.get')
    def test_get_mac_vendor_request_exception(self, mock_requests_get):
        # Mock the requests.get to raise a RequestException
        mock_requests_get.side_effect = Exception

        # Call the function
        vendor = get_mac_vendor('00:11:22:33:44:55')

        # Assert that the function returns None
        self.assertIsNone(vendor)

if __name__ == '__main__':
    unittest.main()
