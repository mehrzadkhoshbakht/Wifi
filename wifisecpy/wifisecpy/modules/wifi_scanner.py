import subprocess
import json

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
            check=True
        )
        networks = json.loads(result.stdout)
        return networks
    except FileNotFoundError:
        print("Error: 'termux-wifi-scaninfo' command not found. Make sure you are running this on Termux with the Termux:API app installed.")
        return None
    except subprocess.CalledProcessError as e:
        print(f"Error executing 'termux-wifi-scaninfo': {e}")
        return None
