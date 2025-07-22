import requests
from scapy.all import ARP, Ether, srp
import logging

def get_mac_vendor(mac_address):
    """
    Gets the vendor of a MAC address using the macvendors.com API.

    Args:
        mac_address: The MAC address to look up.

    Returns:
        The vendor of the MAC address, or None if not found.
    """
    url = f"https://api.macvendors.com/{mac_address}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            logging.warning(f"Could not get vendor for MAC address {mac_address}. Status code: {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Error getting vendor for MAC address {mac_address}: {e}")
        return None

def discover_devices(network_range):
    """
    Discovers devices on the network using ARP requests.

    Args:
        network_range: The network range to scan (e.g., "192.168.1.0/24").

    Returns:
        A list of dictionaries, where each dictionary represents a device.
    """
    devices = []
    try:
        arp = ARP(pdst=network_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        result = srp(packet, timeout=3, verbose=0)[0]

        for sent, received in result:
            vendor = get_mac_vendor(received.hwsrc)
            devices.append({'ip': received.psrc, 'mac': received.hwsrc, 'vendor': vendor})
    except Exception as e:
        logging.error(f"Error discovering devices: {e}")

    return devices
