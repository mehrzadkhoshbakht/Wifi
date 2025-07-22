import typer
import netifaces
import configparser
import os
import logging
from modules.wifi_scanner import scan_wifi_networks
from modules.device_discoverer import discover_devices
from modules.port_scanner import scan_ports
from tqdm import tqdm
from modules.vulnerability_scanner import check_vulnerabilities, get_os, get_service_versions, scan_for_cves
from modules.report_generator import generate_html_report, generate_pdf_report, generate_csv_report
from modules.wireless_attacker import deauthentication_attack
from modules.password_cracker import crack_ftp_password, crack_ssh_password, crack_wpa_password

app = typer.Typer()
config = configparser.ConfigParser()
config.read('wifisecpy/config.ini')

def setup_logging(config):
    log_file = config.get('logging', 'log_file', fallback='wifisecpy.log')
    log_level_str = config.get('logging', 'log_level', fallback='INFO').upper()
    log_level = getattr(logging, log_level_str, logging.INFO)

    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

@app.command()
def scan(
    wifi: bool = typer.Option(False, "--wifi", help="Scan for nearby WiFi networks."),
    devices: bool = typer.Option(False, "--devices", help="Discover devices on the network."),
    ports: str = typer.Option(None, "--ports", help="Scan for open ports on a specific IP address."),
    port_range: str = typer.Option(config.get('scan', 'default_port_range'), "--port-range", help="The port range to scan."),
    os: bool = typer.Option(False, "--os", help="Perform an OS scan on all discovered devices (requires root)."),
    services: bool = typer.Option(False, "--services", help="Perform a service version scan on all discovered devices."),
):
    """
    Scan for WiFi networks, devices, ports, OS, and services.
    """
    if wifi:
        logging.info("Scanning for WiFi networks...")
        networks = scan_wifi_networks()
        if networks:
            for network in networks:
                logging.info(f"SSID: {network['ssid']}, BSSID: {network['bssid']}, Signal: {network['rssi']}, Capabilities: {network['capabilities']}")
    if devices:
        logging.info("Discovering devices on the network...")
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][0]
            network_range = f"{default_gateway.rsplit('.', 1)[0]}.0/24"
            devices = discover_devices(network_range)
            if devices:
                logging.info("Discovered devices:")
                for device in devices:
                    vendor = f"({device['vendor']})" if device['vendor'] else ""
                    logging.info(f"  IP: {device['ip']}, MAC: {device['mac']} {vendor}")
        except Exception as e:
            logging.error(f"Error discovering devices: {e}")
    if ports:
        logging.info(f"Scanning ports on {ports}...")
        ports_to_scan = []
        if "-" in port_range:
            start, end = map(int, port_range.split('-'))
            ports_to_scan = range(start, end + 1)
        else:
            ports_to_scan = [int(p) for p in port_range.split(',')]

        open_ports = scan_ports(ports, ports_to_scan)
        if open_ports:
            logging.info(f"Open ports on {ports}: {open_ports}")
    if os:
        logging.info("Performing OS scan on all discovered devices (requires root)...")
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][0]
            network_range = f"{default_gateway.rsplit('.', 1)[0]}.0/24"
            devices = discover_devices(network_range)
            if devices:
                for device in devices:
                    os_info = get_os(device['ip'])
                    if os_info:
                        logging.info(f"  IP: {device['ip']}, OS: {os_info}")
        except Exception as e:
            logging.error(f"Error during OS scan: {e}")
    if services:
        logging.info("Performing service version scan on all discovered devices...")
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][0]
            network_range = f"{default_gateway.rsplit('.', 1)[0]}.0/24"
            devices = discover_devices(network_range)
            if devices:
                ports_to_scan = range(1, 1025)
                for device in devices:
                    logging.info(f"Scanning services on {device['ip']}...")
                    services = get_service_versions(device['ip'], ports_to_scan)
                    if services:
                        for port, service in services.items():
                            logging.info(f"  Port {port}: {service}")
        except Exception as e:
            logging.error(f"Error during service scan: {e}")

@app.command()
def crack(
    wpa: bool = typer.Option(False, "--wpa", help="Crack a WPA/WPA2 password."),
    cap_file: str = typer.Option(None, "--cap-file", help="The path to the .cap file containing the handshake."),
    password_list: str = typer.Option(None, "--password-list", help="The path to the password list."),
):
    """
    Crack WPA/WPA2 passwords.
    """
    if wpa:
        if not cap_file or not password_list:
            logging.error("Please provide both a .cap file and a password list.")
            return
        crack_wpa_password(cap_file, password_list)

@app.command()
def attack(
    deauth: bool = typer.Option(False, "--deauth", help="Perform a deauthentication attack."),
    target_mac: str = typer.Option(None, "--target-mac", help="The MAC address of the target device."),
    gateway_mac: str = typer.Option(None, "--gateway-mac", help="The MAC address of the gateway."),
    iface: str = typer.Option("wlan0", "--iface", help="The wireless interface to use for the attack."),
):
    """
    Perform a deauthentication attack.
    """
    if deauth:
        if not target_mac or not gateway_mac:
            logging.error("Please provide both a target MAC address and a gateway MAC address.")
            return
        deauthentication_attack(target_mac, gateway_mac, iface)

@app.command()
def report(
    output_path: str = typer.Option(config.get('report', 'default_output_path'), "--output-path", help="The path to save the report."),
    report_format: str = typer.Option("html", "--format", help="The format of the report (html, pdf, csv)."),
):
    """
    Generate a security report.
    """
    logging.info("Generating a security report...")
    report_data = {
        "wifi_networks": scan_wifi_networks(),
        "discovered_devices": [],
        "port_scan_results": [],
        "vulnerability_results": [],
        "os_results": [],
        "service_results": [],
        "cve_results": [],
    }

    try:
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET][0]
        network_range = f"{default_gateway.rsplit('.', 1)[0]}.0/24"
        devices = discover_devices(network_range)
        report_data["discovered_devices"] = devices

        if devices:
            ports_to_scan = range(1, 1025)
            for device in devices:
                logging.info(f"Scanning ports on {device['ip']}...")
                open_ports = scan_ports(device['ip'], ports_to_scan)
                if open_ports:
                    report_data["port_scan_results"].append({"ip": device['ip'], "open_ports": open_ports})
                    vulnerabilities = check_vulnerabilities(open_ports)
                    if vulnerabilities:
                        report_data["vulnerability_results"].append({"ip": device['ip'], "vulnerabilities": vulnerabilities})
                os_info = get_os(device['ip'])
                if os_info:
                    report_data["os_results"].append({"ip": device['ip'], "os": os_info})
                services = get_service_versions(device['ip'], open_ports)
                if services:
                    report_data["service_results"].append({"ip": device['ip'], "services": services})
                    cves = scan_for_cves(services)
                    if cves:
                        report_data["cve_results"].append({"ip": device['ip'], "cves": cves})
    except Exception as e:
        logging.error(f"Error during full scan: {e}")


    logging.info(f"Generating report at {output_path}...")
    try:
        if report_format == "html":
            generate_html_report(report_data, "wifisecpy/templates/report_template.html", output_path)
        elif report_format == "pdf":
            generate_pdf_report(report_data, output_path)
        elif report_format == "csv":
            generate_csv_report(report_data, output_path)
        logging.info("Report generated successfully.")
    except Exception as e:
        logging.error(f"Error generating report: {e}")

if __name__ == "__main__":
    setup_logging(config)
    app()
