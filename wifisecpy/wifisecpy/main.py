import argparse
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

def interactive_mode(config):
    while True:
        logging.info("\nWiFiSecPy Interactive Mode")
        logging.info("1. scan-wifi")
        logging.info("2. discover-devices")
        logging.info("3. scan-ports")
        logging.info("4. full-scan")
        logging.info("5. deauth")
        logging.info("6. crack-wpa")
        logging.info("7. exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            os.system("python wifisecpy/main.py scan-wifi")
        elif choice == "2":
            os.system("python wifisecpy/main.py discover-devices")
        elif choice == "3":
            ip_address = input("Enter the IP address to scan: ")
            ports = input(f"Enter the port range to scan (default: {config.get('scan', 'default_port_range')}): ")
            if not ports:
                ports = config.get('scan', 'default_port_range')
            os.system(f"python wifisecpy/main.py scan-ports {ip_address} --ports {ports}")
        elif choice == "4":
            report_format = input("Enter the report format (html, pdf, csv): ")
            output_report = input(f"Enter the path to save the report (default: {config.get('report', 'default_output_path')}.{report_format}): ")
            if not output_report:
                output_report = f"{config.get('report', 'default_output_path')}.{report_format}"
            os.system(f"python wifisecpy/main.py full-scan --output-report {output_report} --report-format {report_format}")
        elif choice == "5":
            target_mac = input("Enter the target MAC address: ")
            gateway_mac = input("Enter the gateway MAC address: ")
            iface = input("Enter the wireless interface (default: wlan0): ")
            if not iface:
                iface = "wlan0"
            os.system(f"python wifisecpy/main.py deauth {target_mac} {gateway_mac} --iface {iface}")
        elif choice == "6":
            cap_file = input("Enter the path to the .cap file: ")
            password_list_path = input("Enter the path to the password list: ")
            os.system(f"python wifisecpy/main.py crack-wpa {cap_file} {password_list_path}")
        elif choice == "7":
            break
        else:
            logging.warning("Invalid choice. Please try again.")

def main():
    config = configparser.ConfigParser()
    config.read('wifisecpy/config.ini')
    setup_logging(config)

    parser = argparse.ArgumentParser(description="WiFiSecPy - WiFi and Network Security Tool")
    subparsers = parser.add_subparsers(dest="command")

    # Interactive mode
    interactive_parser = subparsers.add_parser("interactive", help="Run in interactive mode.")

    # Scan WiFi
    scan_wifi_parser = subparsers.add_parser("scan-wifi", help="Scan for nearby WiFi networks.")

    # Discover devices
    discover_devices_parser = subparsers.add_parser("discover-devices", help="Discover devices on the network.")

    # Scan ports
    scan_ports_parser = subparsers.add_parser("scan-ports", help="Scan for open ports on a specific IP address.")
    scan_ports_parser.add_argument("ip_address", help="The IP address to scan.")
    scan_ports_parser.add_argument("--ports", type=str, default=config.get('scan', 'default_port_range'), help="The port range to scan (e.g., '1-1024', '80,443').")

    # OS scan
    os_scan_parser = subparsers.add_parser("os-scan", help="Perform an OS scan on all discovered devices (requires root).")

    # Service scan
    service_scan_parser = subparsers.add_parser("service-scan", help="Perform a service version scan on all discovered devices.")

    # Deauthentication attack
    deauth_parser = subparsers.add_parser("deauth", help="Perform a deauthentication attack.")
    deauth_parser.add_argument("target_mac", help="The MAC address of the target device.")
    deauth_parser.add_argument("gateway_mac", help="The MAC address of the gateway.")
    deauth_parser.add_argument("--iface", default="wlan0", help="The wireless interface to use for the attack.")

    # Crack WPA password
    crack_wpa_parser = subparsers.add_parser("crack-wpa", help="Crack a WPA/WPA2 password.")
    crack_wpa_parser.add_argument("cap_file", help="The path to the .cap file containing the handshake.")
    crack_wpa_parser.add_argument("password_list", help="The path to the password list.")

    # Full scan
    full_scan_parser = subparsers.add_parser("full-scan", help="Perform a full scan.")
    full_scan_parser.add_argument("--output-report", type=str, default=config.get('report', 'default_output_path'), help="The path to save the report.")
    full_scan_parser.add_argument("--report-format", type=str, default="html", help="The format of the report (html, pdf, csv).")

    args = parser.parse_args()

    if args.command == "interactive":
        interactive_mode(config)
    elif args.command == "scan-wifi":
        logging.info("Scanning for WiFi networks...")
        networks = scan_wifi_networks()
        if networks:
            for network in networks:
                logging.info(f"SSID: {network['ssid']}, BSSID: {network['bssid']}, Signal: {network['rssi']}, Capabilities: {network['capabilities']}")
    elif args.command == "discover-devices":
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
    elif args.command == "scan-ports":
        logging.info(f"Scanning ports on {args.ip_address}...")
        ports_to_scan = []
        if "-" in args.ports:
            start, end = map(int, args.ports.split('-'))
            ports_to_scan = range(start, end + 1)
        else:
            ports_to_scan = [int(p) for p in args.ports.split(',')]

        open_ports = scan_ports(args.ip_address, ports_to_scan)
        if open_ports:
            logging.info(f"Open ports on {args.ip_address}: {open_ports}")
    elif args.command == "os-scan":
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
    elif args.command == "service-scan":
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
    elif args.command == "deauth":
        deauthentication_attack(args.target_mac, args.gateway_mac, args.iface)
    elif args.command == "crack-wpa":
        crack_wpa_password(args.cap_file, args.password_list)
    elif args.command == "full-scan":
        logging.info("Performing a full scan...")
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


        if args.output_report:
            logging.info(f"Generating report at {args.output_report}...")
            try:
                if args.report_format == "html":
                    generate_html_report(report_data, "wifisecpy/templates/report_template.html", args.output_report)
                elif args.report_format == "pdf":
                    generate_pdf_report(report_data, args.output_report)
                elif args.report_format == "csv":
                    generate_csv_report(report_data, args.output_report)
                logging.info("Report generated successfully.")
            except Exception as e:
                logging.error(f"Error generating report: {e}")

if __name__ == "__main__":
    main()
