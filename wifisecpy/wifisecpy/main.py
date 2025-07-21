import argparse
import netifaces
import configparser
from modules.wifi_scanner import scan_wifi_networks
from modules.device_discoverer import discover_devices
from modules.port_scanner import scan_ports
from tqdm import tqdm
from modules.vulnerability_scanner import check_vulnerabilities, get_os, get_service_versions
from modules.report_generator import generate_html_report, generate_pdf_report, generate_csv_report
from modules.wireless_attacker import deauthentication_attack
from modules.password_cracker import crack_ftp_password, crack_ssh_password

def interactive_mode(config):
    while True:
        print("\nWiFiSecPy Interactive Mode")
        print("1. Scan for WiFi networks")
        print("2. Discover devices on the network")
        print("3. Scan for open ports on a specific IP address")
        print("4. Perform a full scan")
        print("5. Perform a deauthentication attack")
        print("6. Crack a password")
        print("7. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            print("Scanning for WiFi networks...")
            networks = scan_wifi_networks()
            if networks:
                for network in networks:
                    print(f"SSID: {network['ssid']}, BSSID: {network['bssid']}, Signal: {network['rssi']}, Capabilities: {network['capabilities']}")
        elif choice == "2":
            print("Discovering devices on the network...")
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][0]
            network_range = f"{default_gateway.rsplit('.', 1)[0]}.0/24"
            devices = discover_devices(network_range)
            if devices:
                print("Discovered devices:")
                for device in devices:
                    vendor = f"({device['vendor']})" if device['vendor'] else ""
                    print(f"  IP: {device['ip']}, MAC: {device['mac']} {vendor}")
        elif choice == "3":
            ip_address = input("Enter the IP address to scan: ")
            ports = input(f"Enter the port range to scan (default: {config.get('scan', 'default_port_range')}): ")
            if not ports:
                ports = config.get('scan', 'default_port_range')
            print(f"Scanning ports on {ip_address}...")
            ports_to_scan = []
            if "-" in ports:
                start, end = map(int, ports.split('-'))
                ports_to_scan = range(start, end + 1)
            else:
                ports_to_scan = [int(p) for p in ports.split(',')]

            with tqdm(total=len(ports_to_scan), desc="Scanning Ports") as pbar:
                open_ports = scan_ports(ip_address, ports_to_scan, pbar)
            if open_ports:
                print(f"Open ports on {ip_address}: {open_ports}")
        elif choice == "4":
            report_format = input("Enter the report format (html, pdf, csv): ")
            output_report = input(f"Enter the path to save the report (default: {config.get('report', 'default_output_path')}.{report_format}): ")
            if not output_report:
                output_report = f"{config.get('report', 'default_output_path')}.{report_format}"
            print("Performing a full scan...")
            report_data = {
                "wifi_networks": scan_wifi_networks(),
                "discovered_devices": [],
                "port_scan_results": [],
                "vulnerability_results": [],
                "os_results": [],
                "service_results": [],
                "cve_results": [],
            }

            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][0]
            network_range = f"{default_gateway.rsplit('.', 1)[0]}.0/24"
            with tqdm(total=254, desc="Discovering Devices") as pbar:
                devices = discover_devices(network_range)
            report_data["discovered_devices"] = devices

            if devices:
                ports_to_scan = range(1, 1025)
                for device in devices:
                    print(f"Scanning {device['ip']}...")
                    with tqdm(total=len(ports_to_scan), desc=f"Scanning Ports on {device['ip']}") as pbar:
                        open_ports = scan_ports(device['ip'], ports_to_scan, pbar)
                    if open_ports:
                        report_data["port_scan_results"].append({"ip": device['ip'], "open_ports": open_ports})
                        vulnerabilities = check_vulnerabilities(open_ports)
                        if vulnerabilities:
                            report_data["vulnerability_results"].append({"ip": device['ip'], "vulnerabilities": vulnerabilities})
                        services = get_service_versions(device['ip'], open_ports)
                        if services:
                            report_data["service_results"].append({"ip": device['ip'], "services": services})
                            cves = scan_for_cves(services)
                            if cves:
                                report_data["cve_results"].append({"ip": device['ip'], "cves": cves})
                        os = get_os(device['ip'])
                        if os:
                            report_data["os_results"].append({"ip": device['ip'], "os": os})

            if output_report:
                print(f"Generating report at {output_report}...")
                if report_format == "html":
                    generate_html_report(report_data, "wifisecpy/templates/report_template.html", output_report)
                elif report_format == "pdf":
                    generate_pdf_report(report_data, output_report)
                elif report_format == "csv":
                    generate_csv_report(report_data, output_report)
                print("Report generated successfully.")
        elif choice == "5":
            target_mac = input("Enter the target MAC address: ")
            gateway_mac = input("Enter the gateway MAC address: ")
            deauthentication_attack(target_mac, gateway_mac)
        elif choice == "6":
            service = input("Enter the service to crack (ftp or ssh): ")
            hostname = input("Enter the hostname or IP address: ")
            username = input("Enter the username: ")
            password_list_path = input("Enter the path to the password list: ")
            with open(password_list_path, "r") as f:
                password_list = [line.strip() for line in f]
            if service == "ftp":
                crack_ftp_password(hostname, username, password_list)
            elif service == "ssh":
                crack_ssh_password(hostname, username, password_list)
            else:
                print("Invalid service. Please try again.")
        elif choice == "7":
            break
        else:
            print("Invalid choice. Please try again.")

def main():
    config = configparser.ConfigParser()
    config.read('wifisecpy/config.ini')

    parser = argparse.ArgumentParser(description="WiFiSecPy - WiFi and Network Security Tool")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode.")
    parser.add_argument("--scan-wifi", action="store_true", help="Scan for nearby WiFi networks.")
    parser.add_argument("--discover-devices", action="store_true", help="Discover devices on the network.")
    parser.add_argument("--scan-ports", type=str, help="Scan for open ports on a specific IP address.")
    parser.add_argument("--ports", type=str, default=config.get('scan', 'default_port_range'), help="The port range to scan (e.g., '1-1024', '80,443').")
    parser.add_argument("--os-scan", action="store_true", help="Perform an OS scan on all discovered devices (requires root).")
    parser.add_argument("--service-scan", action="store_true", help="Perform a service version scan on all discovered devices.")
    parser.add_argument("--full-scan", action="store_true", help="Perform a full scan (discover devices, scan ports, check vulnerabilities).")
    parser.add_argument("--output-report", type=str, default=config.get('report', 'default_output_path'), help="The path to save the report.")
    parser.add_argument("--report-format", type=str, default="html", help="The format of the report (html, pdf, csv).")

    args = parser.parse_args()

    if args.interactive:
        interactive_mode()
        return

    if args.scan_wifi:
        print("Scanning for WiFi networks...")
        networks = scan_wifi_networks()
        if networks:
            for network in networks:
                print(f"SSID: {network['ssid']}, BSSID: {network['bssid']}, Signal: {network['rssi']}, Capabilities: {network['capabilities']}")

    if args.discover_devices or args.full_scan:
        print("Discovering devices on the network...")
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET][0]
        network_range = f"{default_gateway.rsplit('.', 1)[0]}.0/24"
        devices = discover_devices(network_range)
        if devices:
            print("Discovered devices:")
            for device in devices:
                vendor = f"({device['vendor']})" if device['vendor'] else ""
                print(f"  IP: {device['ip']}, MAC: {device['mac']} {vendor}")

    if args.scan_ports:
        print(f"Scanning ports on {args.scan_ports}...")
        ports_to_scan = []
        if "-" in args.ports:
            start, end = map(int, args.ports.split('-'))
            ports_to_scan = range(start, end + 1)
        else:
            ports_to_scan = [int(p) for p in args.ports.split(',')]

        open_ports = scan_ports(args.scan_ports, ports_to_scan)
        if open_ports:
            print(f"Open ports on {args.scan_ports}: {open_ports}")

    if args.os_scan:
        print("Performing OS scan on all discovered devices (requires root)...")
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET][0]
        network_range = f"{default_gateway.rsplit('.', 1)[0]}.0/24"
        devices = discover_devices(network_range)
        if devices:
            for device in devices:
                os = get_os(device['ip'])
                if os:
                    print(f"  IP: {device['ip']}, OS: {os}")

    if args.service_scan:
        print("Performing service version scan on all discovered devices...")
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET][0]
        network_range = f"{default_gateway.rsplit('.', 1)[0]}.0/24"
        devices = discover_devices(network_range)
        if devices:
            ports_to_scan = range(1, 1025)
            for device in devices:
                print(f"Scanning services on {device['ip']}...")
                services = get_service_versions(device['ip'], ports_to_scan)
                if services:
                    for port, service in services.items():
                        print(f"  Port {port}: {service}")

    if args.full_scan:
        report_data = {
            "wifi_networks": scan_wifi_networks(),
            "discovered_devices": [],
            "port_scan_results": [],
            "vulnerability_results": [],
            "os_results": [],
            "service_results": [],
            "cve_results": [],
        }

        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET][0]
        network_range = f"{default_gateway.rsplit('.', 1)[0]}.0/24"
        devices = discover_devices(network_range)
        report_data["discovered_devices"] = devices

        if devices:
            ports_to_scan = range(1, 1025)
            for device in devices:
                print(f"Scanning ports on {device['ip']}...")
                open_ports = scan_ports(device['ip'], ports_to_scan)
                if open_ports:
                    report_data["port_scan_results"].append({"ip": device['ip'], "open_ports": open_ports})
                    vulnerabilities = check_vulnerabilities(open_ports)
                    if vulnerabilities:
                        report_data["vulnerability_results"].append({"ip": device['ip'], "vulnerabilities": vulnerabilities})
                if args.os_scan:
                    os = get_os(device['ip'])
                    if os:
                        report_data["os_results"].append({"ip": device['ip'], "os": os})
                if args.service_scan:
                    services = get_service_versions(device['ip'], open_ports)
                    if services:
                        report_data["service_results"].append({"ip": device['ip'], "services": services})
                        cves = scan_for_cves(services)
                        if cves:
                            report_data["cve_results"].append({"ip": device['ip'], "cves": cves})


        if args.output_report:
            print(f"Generating report at {args.output_report}...")
            if args.report_format == "html":
                generate_html_report(report_data, "wifisecpy/templates/report_template.html", args.output_report)
            elif args.report_format == "pdf":
                generate_pdf_report(report_data, args.output_report)
            elif args.report_format == "csv":
                generate_csv_report(report_data, args.output_report)
            print("Report generated successfully.")

if __name__ == "__main__":
    main()
