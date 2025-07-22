import unittest
import sys
import os
from unittest.mock import patch, Mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from wifisecpy.modules.password_cracker import crack_wpa_password

class TestPasswordCracker(unittest.TestCase):
    @patch('subprocess.run')
    def test_crack_wpa_password_success(self, mock_subprocess_run):
        # Mock the subprocess.run to return a successful result
        mock_process = Mock()
        mock_process.stdout = 'KEY FOUND! [ test_password ]'
        mock_subprocess_run.return_value = mock_process

        # Call the function
        crack_wpa_password('test.cap', 'passwords.txt')

        # Assert that the subprocess.run function was called with the correct arguments
        mock_subprocess_run.assert_called_with(
            ['aircrack-ng', '-w', 'passwords.txt', 'test.cap'],
            capture_output=True,
            text=True,
            check=True,
        )

if __name__ == '__main__':
    unittest.main()
