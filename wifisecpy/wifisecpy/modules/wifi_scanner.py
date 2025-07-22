import subprocess
import json
import logging


def scan_wifi_networks():
    """
    Scans for nearby WiFi networks using the termux-wifi-scaninfo command.

    Returns:
        A list of dictionaries, where each dictionary represents a WiFi network.
    """
    try:
        result = subprocess.run(
            ["termux-wifi-scaninfo"],
            capture_output=True,
            text=True,
            check=True,
        )
        networks = json.loads(result.stdout)
        return networks
    except FileNotFoundError:
        logging.error(
            "Error: 'termux-wifi-scaninfo' command not found. Make sure you "
            "are running this on Termux with the Termux:API app installed."
        )
        return None
    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing 'termux-wifi-scaninfo': {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from 'termux-wifi-scaninfo': {e}")
        return None
