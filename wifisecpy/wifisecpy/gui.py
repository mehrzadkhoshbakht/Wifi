import tkinter as tk
from tkinter import scrolledtext
import subprocess

def run_command(command, output_widget):
    output_widget.delete(1.0, tk.END)
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
        text=True,
        bufsize=1,
        universal_newlines=True,
    )
    for line in process.stdout:
        output_widget.insert(tk.END, line)
        output_widget.see(tk.END)
    process.wait()

def create_gui():
    root = tk.Tk()
    root.title("WiFiSecPy")

    main_frame = tk.Frame(root)
    main_frame.pack(padx=10, pady=10)

    # --- Buttons ---
    button_frame = tk.Frame(main_frame)
    button_frame.pack(pady=5)

    scan_wifi_button = tk.Button(
        button_frame,
        text="Scan WiFi",
        command=lambda: run_command("python wifisecpy/main.py scan --wifi", output_area),
    )
    scan_wifi_button.pack(side=tk.LEFT, padx=5)

    discover_devices_button = tk.Button(
        button_frame,
        text="Discover Devices",
        command=lambda: run_command("python wifisecpy/main.py scan --devices", output_area),
    )
    discover_devices_button.pack(side=tk.LEFT, padx=5)

    # --- Output Area ---
    output_area = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, width=80, height=20)
    output_area.pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
