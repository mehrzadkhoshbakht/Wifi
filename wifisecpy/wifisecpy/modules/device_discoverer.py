from scapy.all import ARP, Ether, srp

def discover_devices(network_range):
    """
    Discovers devices on the network using ARP requests.

    Args:
        network_range: The network range to scan (e.g., "192.168.1.0/24").

    Returns:
        A list of dictionaries, where each dictionary represents a device.
    """
    arp = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices
