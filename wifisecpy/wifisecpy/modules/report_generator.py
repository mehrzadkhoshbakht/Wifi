import csv
from jinja2 import Environment, FileSystemLoader
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
import logging

def generate_html_report(data, template_path, output_path):
    """
    Generates an HTML report from a template.

    Args:
        data: A dictionary containing the data to be included in the report.
        template_path: The path to the Jinja2 template.
        output_path: The path to save the generated report.
    """
    try:
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template(template_path)
        html = template.render(data)

        with open(output_path, "w") as f:
            f.write(html)
    except Exception as e:
        logging.error(f"Error generating HTML report: {e}")

def generate_pdf_report(data, output_path):
    """
    Generates a PDF report.

    Args:
        data: A dictionary containing the data to be included in the report.
        output_path: The path to save the generated report.
    """
    try:
        doc = SimpleDocTemplate(output_path, pagesize=letter)
        elements = []

        # Title
        elements.append(Table([["WiFiSecPy Security Report"]], style=[('ALIGN', (0, 0), (-1, -1), 'CENTER'), ('FONTSIZE', (0, 0), (-1, -1), 18)]))

        # Discovered Devices
        elements.append(Table([["Discovered Devices"]], style=[('ALIGN', (0, 0), (-1, -1), 'CENTER'), ('FONTSIZE', (0, 0), (-1, -1), 14)]))
        device_data = [["IP Address", "MAC Address", "Vendor"]]
        for device in data.get("discovered_devices", []):
            device_data.append([device.get("ip"), device.get("mac"), device.get("vendor", "N/A")])
        elements.append(Table(device_data))

        # Open Ports
        elements.append(Table([["Open Ports"]], style=[('ALIGN', (0, 0), (-1, -1), 'CENTER'), ('FONTSIZE', (0, 0), (-1, -1), 14)]))
        port_data = [["IP Address", "Open Ports"]]
        for result in data.get("port_scan_results", []):
            port_data.append([result.get("ip"), ", ".join(map(str, result.get("open_ports", [])))])
        elements.append(Table(port_data))

        # Vulnerabilities
        elements.append(Table([["Vulnerabilities"]], style=[('ALIGN', (0, 0), (-1, -1), 'CENTER'), ('FONTSIZE', (0, 0), (-1, -1), 14)]))
        vuln_data = [["IP Address", "Port", "Vulnerability"]]
        for result in data.get("vulnerability_results", []):
            for port, vuln in result.get("vulnerabilities", {}).items():
                vuln_data.append([result.get("ip"), port, vuln])
        elements.append(Table(vuln_data))

        doc.build(elements)
    except Exception as e:
        logging.error(f"Error generating PDF report: {e}")

def generate_csv_report(data, output_path):
    """
    Generates a CSV report.

    Args:
        data: A dictionary containing the data to be included in the report.
        output_path: The path to save the generated report.
    """
    try:
        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)

            writer.writerow(["Discovered Devices"])
            writer.writerow(["IP Address", "MAC Address", "Vendor"])
            for device in data.get("discovered_devices", []):
                writer.writerow([device.get("ip"), device.get("mac"), device.get("vendor", "N/A")])

            writer.writerow([])
            writer.writerow(["Open Ports"])
            writer.writerow(["IP Address", "Open Ports"])
            for result in data.get("port_scan_results", []):
                writer.writerow([result.get("ip"), ", ".join(map(str, result.get("open_ports", [])))])

            writer.writerow([])
            writer.writerow(["Vulnerabilities"])
            writer.writerow(["IP Address", "Port", "Vulnerability"])
            for result in data.get("vulnerability_results", []):
                for port, vuln in result.get("vulnerabilities", {}).items():
                    writer.writerow([result.get("ip"), port, vuln])
    except Exception as e:
        logging.error(f"Error generating CSV report: {e}")
