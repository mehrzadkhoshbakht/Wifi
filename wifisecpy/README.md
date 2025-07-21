# WiFiSecPy

WiFiSecPy is a Python-based security tool for testing the security of wireless networks and devices. It is designed to run on Android devices using Termux, without requiring root access.

## Features

*   Scan for nearby WiFi networks.
*   Discover devices connected to the network.
*   Scan for open ports on network devices.
*   Check for basic vulnerabilities.
*   Generate a professional HTML report.

## Installation

1.  **Install Termux and Termux:API:**
    *   Download and install Termux from F-Droid.
    *   Download and install the Termux:API app from F-Droid.

2.  **Install Dependencies:**
    *   Open Termux and run the following commands:
        ```bash
        pkg install python nmap termux-api
        pip install -r requirements.txt
        ```

3.  **Clone the Repository:**
    ```bash
    git clone https://github.com/your-username/wifisecpy.git
    cd wifisecpy
    ```

## Usage

### Scan for WiFi Networks
```bash
python wifisecpy/main.py --scan-wifi
```

### Discover Devices on the Network
```bash
python wifisecpy/main.py --discover-devices
```

### Scan for Open Ports
```bash
python wifisecpy/main.py --scan-ports <ip_address> --ports <port_range>
```
**Example:**
```bash
python wifisecpy/main.py --scan-ports 192.168.1.1 --ports 1-1024
```

### Perform a Full Scan and Generate a Report
```bash
python wifisecpy/main.py --full-scan --output-report reports/scan_report.html
```

## Disclaimer

This tool is intended for educational purposes and for testing networks only with the owner's explicit permission. Unauthorized scanning of networks is illegal. The developers of this tool are not responsible for any misuse or damage caused by this tool.
