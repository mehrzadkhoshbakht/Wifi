import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from wifisecpy.modules.report_generator import generate_html_report, generate_pdf_report, generate_csv_report

class TestReportGenerator(unittest.TestCase):
    def setUp(self):
        self.data = {
            "discovered_devices": [
                {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "vendor": "Test Vendor"}
            ],
            "port_scan_results": [
                {"ip": "192.168.1.1", "open_ports": [80, 443]}
            ],
            "vulnerability_results": [
                {"ip": "192.168.1.1", "vulnerabilities": {80: "HTTP (No Encryption)"}}
            ]
        }
        self.template_path = "wifisecpy/templates/report_template.html"
        self.output_path = "test_report"

    def tearDown(self):
        if os.path.exists(f"{self.output_path}.html"):
            os.remove(f"{self.output_path}.html")
        if os.path.exists(f"{self.output_path}.pdf"):
            os.remove(f"{self.output_path}.pdf")
        if os.path.exists(f"{self.output_path}.csv"):
            os.remove(f"{self.output_path}.csv")

    def test_generate_html_report(self):
        generate_html_report(self.data, self.template_path, f"{self.output_path}.html")
        self.assertTrue(os.path.exists(f"{self.output_path}.html"))

    def test_generate_pdf_report(self):
        generate_pdf_report(self.data, f"{self.output_path}.pdf")
        self.assertTrue(os.path.exists(f"{self.output_path}.pdf"))

    def test_generate_csv_report(self):
        generate_csv_report(self.data, f"{self.output_path}.csv")
        self.assertTrue(os.path.exists(f"{self.output_path}.csv"))

if __name__ == '__main__':
    unittest.main()
