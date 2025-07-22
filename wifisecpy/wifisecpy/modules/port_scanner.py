import socket
from tqdm import tqdm
import logging

def scan_ports(ip_address, ports, progress_bar=None):
    """
    Scans for open TCP ports on a given IP address.

    Args:
        ip_address: The IP address to scan.
        ports: A list of ports to scan.
        progress_bar: A tqdm progress bar object.

    Returns:
        A list of open ports.
    """
    open_ports = []
    iterable = tqdm(ports) if progress_bar is None else ports
    for port in iterable:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip_address, port))
                if result == 0:
                    open_ports.append(port)
        except socket.error as e:
            logging.error(f"Error scanning port {port} on {ip_address}: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred while scanning port {port} on {ip_address}: {e}")
        if progress_bar:
            progress_bar.update(1)
    return open_ports
