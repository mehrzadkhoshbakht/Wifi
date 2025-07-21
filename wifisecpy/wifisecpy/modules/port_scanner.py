import socket

def scan_ports(ip_address, ports):
    """
    Scans for open TCP ports on a given IP address.

    Args:
        ip_address: The IP address to scan.
        ports: A list of ports to scan.

    Returns:
        A list of open ports.
    """
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip_address, port))
                if result == 0:
                    open_ports.append(port)
        except socket.error as e:
            print(f"Error scanning port {port}: {e}")
    return open_ports
