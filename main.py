import socket
import subprocess
import sys
import logging
from enum import StrEnum
import time
import json
import re
import threading
import tkinter as tk
from tkinter import messagebox, font, ttk, filedialog

logging.basicConfig(level=logging.INFO)
longitude_entry = ttk.Entry()
latitude_entry = ttk.Entry()
device_connected = False


class MessageType(StrEnum):
    INFO = "info"
    ERROR = "error"
    WARNING = "warning"


def mount_developer_disk_image():
    try:
        result = subprocess.run(
            ["pymobiledevice3", "mounter", "auto-mount"],
            capture_output=True,
            text=True,
            check=True,
        )
        if result.stderr:
            logging.error(f"Error in mounting Developer Disk Image: {result.stderr}")
            return False
        logging.info("Developer Disk Image successfully mounted.")
        return True
    except (subprocess.CalledProcessError, OSError) as e:
        logging.error(f"Mounting error: {e}")
        return False


def save_as():
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*")]
    )

    if file_path:
        try:
            with open(file_path, "w") as file:
                file.write(f"{longitude_entry.get()}, {latitude_entry.get()}")
            show_message("Data saved successfully", MessageType.INFO)
        except OSError as e:
            logging.error(f"Error saving file: {e}")
            show_message("Failed to save the file", MessageType.ERROR)


def load():
    file_path = filedialog.askopenfilename(
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if file_path:
        try:
            with open(file_path, "r") as file:
                long_str, lat_str = file.read().strip().split(",")
                longitude, latitude = float(long_str.strip()), float(lat_str.strip())

                if not validate_coordinates(longitude, latitude):
                    raise ValueError("Invalid longitude or latitude range.")

                longitude_entry.delete(0, tk.END)
                longitude_entry.insert(0, str(longitude))
                latitude_entry.delete(0, tk.END)
                latitude_entry.insert(0, str(latitude))

                show_message("Data loaded successfully", MessageType.INFO)
        except (ValueError, OSError) as e:
            logging.error(f"Error parsing longitude and latitude: {e}")
            show_message("Error loading file or invalid format.", MessageType.ERROR)


def show_message(message: str, message_type=MessageType.INFO):
    message_type_actions = {
        MessageType.INFO: messagebox.showinfo,
        MessageType.ERROR: messagebox.showerror,
        MessageType.WARNING: messagebox.showwarning,
    }

    if message_type in message_type_actions:
        message_type_actions[message_type]("Notification", message)


def monitor_device_connection():
    global device_connected
    while True:
        new_device_connected = check_for_connected_devices()
        if new_device_connected != device_connected:
            device_connected = new_device_connected
            connected_status = "connected" if device_connected else "disconnected"
            logging.info(f"Device {connected_status}")
        time.sleep(5)


def find_free_port(max_attempts: int = 5):
    for attempt in range(max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("", 0))
                return s.getsockname()[1]
        except OSError as e:
            logging.warning(
                f"Error finding free port (Attempt {attempt + 1}/{max_attempts}): {e}"
            )
            time.sleep(1)
    logging.error("Failed to find a free port after max attempts.")
    sys.exit(1)


def get_host_ip(dns_server: str = "1.1.1.1", max_attempts: int = 5):
    for attempt in range(max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((dns_server, 53))  # Use DNS server port 53
                return s.getsockname()[0]
        except OSError as e:
            logging.warning(
                f"Error retrieving host IP (Attempt {attempt + 1}/{max_attempts}): {e}"
            )
            time.sleep(1)
    logging.error("Failed to find a free port after max attempts.")
    sys.exit(1)


def validate_coordinates(longitude: float, latitude: float):
    logging.info(f"Validating coordinates: Longitude={longitude}, Latitude={latitude}")
    if -180 <= latitude <= 180 and -90 <= longitude <= 90:
        return True
    logging.error("Invalid longitude or latitude range.")
    return False


def run_command(command: list[str]):
    try:
        subprocess.run(command, check=True, timeout=10)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as e:
        logging.error(f"Command execution failed: {e}")
        sys.exit(1)


def strip_ansi_codes(text: str):
    ansi_escape = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", text)


def get_ios_version():
    try:
        result = subprocess.run(
            ["pymobiledevice3", "usbmux", "list"],
            capture_output=True,
            text=True,
            check=True,
        )
        clean_output = strip_ansi_codes(result.stdout)
        if not clean_output.strip():
            logging.error("No output returned from 'pymobiledevice3 usbmux list'")
            return None

        devices = json.loads(clean_output)
        if devices:
            return devices[0]["ProductVersion"]
        logging.error("No connected iOS devices found.")
        return None
    except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
        logging.error(f"Error retrieving iOS version: {e}")
        return None


def set_location():
    try:
        longitude = float(longitude_entry.get())
        latitude = float(latitude_entry.get())

        if not validate_coordinates(longitude, latitude):
            raise ValueError("Invalid longitude or latitude range.")

        ios_version = get_ios_version()
        if ios_version is None:
            raise RuntimeError(
                "Failed to retrieve iOS version. Please ensure a device is connected."
            )

        ios_major_version = int(ios_version.split(".")[0])

        if ios_major_version >= 17:
            command: list[str] = [
                "pymobiledevice3",
                "developer",
                "dvt",
                "simulate-location",
                "set",
                "--",
                str(longitude),
                str(latitude),
            ]

            run_command(command)
            show_message(
                f"Location set to longitude: {longitude}, latitude: {latitude}",
                MessageType.INFO,
            )
        else:
            if not mount_developer_disk_image():
                raise RuntimeError("Failed to mount Developer Disk Image.")

    except (ValueError, RuntimeError) as e:
        logging.error(f"Error setting location: {e}")
        show_message(str(e), MessageType.ERROR)


def check_for_connected_devices():
    try:
        result = subprocess.run(
            ["pymobiledevice3", "usbmux", "list"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        clean_output = strip_ansi_codes(result.stdout)
        if clean_output.strip():
            devices = json.loads(clean_output)
            return len(devices) > 0
        logging.info("No connected devices found.")
        return False
    except (
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        json.JSONDecodeError,
    ) as e:
        logging.error(f"Error checking for devices: {e}")
        return False


def main():
    global longitude_entry, latitude_entry, host, port, device_connected

    monitor_thread = threading.Thread(target=monitor_device_connection, daemon=True)
    monitor_thread.start()

    # host = get_host_ip()
    host = "fdee:361:eed5::1"
    # port = find_free_port()
    port = "53384"

    # Create the GUI window
    root = tk.Tk()
    root.title("Location Spoofer")
    root.geometry("600x500")
    root.configure(bg="white")

    style = ttk.Style()
    style.theme_use("clam")

    # Configure style for connection status labels
    style.configure("Connected.TLabel", foreground="green")
    style.configure("Disconnected.TLabel", foreground="red")

    # Font setup
    modern_font = font.Font(family="Helvetica", size=12)

    # Connected status label
    connection_status_label = ttk.Label(
        root, text="", style="Disconnected.TLabel", font=modern_font, background="white"
    )
    connection_status_label.pack(pady=10)

    def updated_connection_status_label():
        if device_connected:
            connection_status_label.config(
                text="Device connected", style="Connected.TLabel"
            )
        else:
            connection_status_label.config(
                text="No device connected", style="Disconnected.TLabel"
            )
        root.after(1000, updated_connection_status_label)

    # Longitude and Latitude input fields
    longitude_label = ttk.Label(
        root, text="Longitude:", font=modern_font, background="white"
    )
    longitude_label.pack()
    longitude_entry = ttk.Entry(root, font=modern_font)
    longitude_entry.pack(pady=5)

    latitude_label = ttk.Label(
        root, text="Latitude:", font=modern_font, background="white"
    )
    latitude_label.pack()
    latitude_entry = ttk.Entry(root, font=modern_font)
    latitude_entry.pack(pady=5)

    # Set Location button
    set_location_button = ttk.Button(root, text="Set Location", command=set_location)
    set_location_button.pack(pady=10)

    load_button = ttk.Button(root, text="Load", command=load)
    load_button.pack(pady=10)

    # Instructions
    instructions = """Instructions:
        - Connect your iOS device.
        - Enter the desired longitude and latitude.
        - Click 'Set Location' to update the device's location.
        - Save or Load long/lat points using the Save/Load buttons.
    """
    instructions_label = ttk.Label(
        root, text=instructions, font=modern_font, justify=tk.LEFT, background="white"
    )
    instructions_label.pack(pady=25)

    updated_connection_status_label()

    root.mainloop()


if __name__ == "__main__":
    main()
