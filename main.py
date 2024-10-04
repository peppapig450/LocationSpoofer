import socket
import subprocess
import sys
import logging
import time
import json
import re
import threading
import tkinter as tk
from tkinter import messagebox, font, ttk, filedialog

logging.basicConfig(level=logging.INFO)
longitude_entry = None
latitude_entry = None
device_connected = False


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
