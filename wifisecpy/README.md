# WiFiSecPy

WiFiSecPy is a Python-based security tool for testing the security of wireless networks and devices. It is designed to run on Android devices using Termux, without requiring root access for most features.

## Features

*   Scan for nearby WiFi networks.
*   Discover devices connected to the network.
*   Scan for open ports on network devices.
*   Check for basic vulnerabilities.
*   Perform deauthentication attacks.
*   Crack WPA/WPA2 passwords.
*   Generate professional reports in HTML, PDF, and CSV formats.

## Installation

1.  **Install Termux and Termux:API:**
    *   Download and install Termux from F-Droid.
    *   Download and install the Termux:API app from F-Droid.

2.  **Install Dependencies:**
    *   Open Termux and run the following commands:
        ```bash
        pkg install python nmap aircrack-ng termux-api
        pip install -r requirements.txt
        ```

3.  **Clone the Repository:**
    ```bash
    git clone https://github.com/your-username/wifisecpy.git
    cd wifisecpy
    ```

## Usage

WiFiSecPy uses a command-line interface (CLI) with sub-commands for each of its functionalities.

### Scan

The `scan` command is used to scan for WiFi networks, devices, ports, OS, and services.

**Usage:**
```bash
python wifisecpy/main.py scan [OPTIONS]
```

**Options:**
*   `--wifi`: Scan for nearby WiFi networks.
*   `--devices`: Discover devices on the network.
*   `--ports <ip_address>`: Scan for open ports on a specific IP address.
*   `--port-range <port_range>`: The port range to scan (e.g., '1-1024', '80,443').
*   `--os`: Perform an OS scan on all discovered devices (requires root).
*   `--services`: Perform a service version scan on all discovered devices.

**Example:**
```bash
python wifisecpy/main.py scan --wifi --devices
```

### Attack

The `attack` command is used to perform attacks, such as a deauthentication attack.

**Usage:**
```bash
python wifisecpy/main.py attack --deauth --target-mac <target_mac> --gateway-mac <gateway_mac> [OPTIONS]
```

**Options:**
*   `--deauth`: Perform a deauthentication attack.
*   `--target-mac <target_mac>`: The MAC address of the target device.
*   `--gateway-mac <gateway_mac>`: The MAC address of the gateway.
*   `--iface <iface>`: The wireless interface to use for the attack (default: wlan0).

**Example:**
```bash
python wifisecpy/main.py attack --deauth --target-mac 00:11:22:33:44:55 --gateway-mac 66:77:88:99:AA:BB
```

### Crack

The `crack` command is used to crack WPA/WPA2 passwords.

**Usage:**
```bash
python wifisecpy/main.py crack --wpa --cap-file <cap_file> --password-list <password_list>
```

**Options:**
*   `--wpa`: Crack a WPA/WPA2 password.
*   `--cap-file <cap_file>`: The path to the .cap file containing the handshake.
*   `--password-list <password_list>`: The path to the password list.

**Example:**
```bash
python wifisecpy/main.py crack --wpa --cap-file handshake.cap --password-list passwords.txt
```

### Report

The `report` command is used to generate a security report.

**Usage:**
```bash
python wifisecpy/main.py report [OPTIONS]
```

**Options:**
*   `--output-path <output_path>`: The path to save the report.
*   `--format <format>`: The format of the report (html, pdf, csv).

**Example:**
```bash
python wifisecpy/main.py report --output-path my_report.html --format html
```

## Disclaimer

This tool is intended for educational purposes and for testing networks only with the owner's explicit permission. Unauthorized scanning of networks is illegal. The developers of this tool are not responsible for any misuse or damage caused by this tool.

## Configuration

WiFiSecPy can be configured using the `config.ini` file. This file allows you to set default values for various options, such as the wireless interface, report formats, and scan parameters.

To modify the configuration, open the `config.ini` file and edit the values under the appropriate sections. For example, you can change the default wireless interface by modifying the `iface` value in the `[General]` section.

## GUI Version

For users who prefer a graphical interface, WiFiSecPy also comes with a GUI version built with Tkinter. To launch the GUI, run the following command:

```bash
python wifisecpy/gui.py
```

The GUI provides access to all the tool's functionalities in a user-friendly way, including scanning, attacking, and reporting.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
