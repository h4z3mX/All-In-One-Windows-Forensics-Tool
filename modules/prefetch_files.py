# prefetch_forensics.py

import os
import struct
import datetime
from tkinter import filedialog, messagebox

# Constants for the Prefetch file format
PRE_HEADER_SIZE = 0x30  # Size of the Prefetch file header
EXECUTABLE_NAME_OFFSET = 0x4C  # Offset where executable name is stored

# Function to parse the Prefetch file
def parse_prefetch_file(prefetch_path):
    try:
        with open(prefetch_path, 'rb') as f:
            # Read the Prefetch file header (first 0x30 bytes)
            header = f.read(PRE_HEADER_SIZE)

            # Ensure we are reading a valid Prefetch file by checking the signature
            signature = header[:4]
            if signature != b'PCFR':
                return None

            # Extract the executable name from the Prefetch file
            f.seek(EXECUTABLE_NAME_OFFSET)
            exe_name = ''
            while True:
                byte = f.read(1)
                if byte == b'\x00':  # Null byte indicates end of string
                    break
                exe_name += byte.decode('ascii')
                
            return exe_name
    
    except Exception as e:
        print(f"Error reading Prefetch file {prefetch_path}: {e}")
        return None

# Function to get recently executed applications
def get_recently_executed_apps(prefetch_dir):
    prefetch_files = [f for f in os.listdir(prefetch_dir) if f.endswith('.pf')]
    
    if not prefetch_files:
        return []
    
    executed_apps = []
    for prefetch_file in prefetch_files:
        prefetch_path = os.path.join(prefetch_dir, prefetch_file)
        app_name = parse_prefetch_file(prefetch_path)
        if app_name:
            executed_apps.append(app_name)
    
    return executed_apps

# Function to start Prefetch Forensics
def start_prefetch_forensics(prefetch_forensics_output):
    prefetch_dir =  r'C:\Windows\Prefetch'
    
    executed_apps = get_recently_executed_apps(prefetch_dir)
    if not executed_apps:
        update_text_widget(prefetch_forensics_output, "No recent applications found.")
    else:
        apps_list = "\n".join(executed_apps)
        update_text_widget(prefetch_forensics_output, apps_list)

# Function to update text widget with analysis results
def update_text_widget(widget, text):
    widget.delete(1.0, "end")
    widget.insert("insert", text)
