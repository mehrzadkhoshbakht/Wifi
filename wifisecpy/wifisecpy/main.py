import argparse
import netifaces
from modules.wifi_scanner import scan_wifi_networks
from modules.device_discoverer import discover_devices
from modules.port_scanner import scan_ports
from modules.vulnerability_scanner import check_vulnerabilities, get_os, get_service_versions
from modules.report_generator import generate_html_report

def main():
    parser = argparse.ArgumentParser(description="WiFiSecPy - WiFi and Network Security Tool")
    parser.add_argument("--scan-wifi", action="store_true", help="Scan for nearby WiFi networks.")
    parser.add_argument("--discover-devices", action="store_true", help="Discover devices on the network.")
    parser.add_argument("--scan-ports", type=str, help="Scan for open ports on a specific IP address.")
    parser.add_argument("--ports", type=str, default="1-1024", help="The port range to scan (e.g., '1-1024', '80,443').")
    parser.add_argument("--os-scan", action="store_true", help="Perform an OS scan on all discovered devices (requires root).")
    parser.add_argument("--service-scan", action="store_true", help="Perform a service version scan on all discovered devices.")
    parser.add_argument("--full-scan", action="store_true", help="Perform a full scan (discover devices, scan ports, check vulnerabilities).")
    parser.add_argument("--output-report", type=str, help="The path to save the HTML report.")

    args = parser.parse_args()

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
            generate_html_report(report_data, "wifisecpy/templates/report_template.html", args.output_report)
            print("Report generated successfully.")

if __name__ == "__main__":
    main()
