import winreg

def collect_startup_entries():
    """Collect startup entries from the registry."""
    startup_entries = []
    startup_keys = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    ]
    for key in startup_keys:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key) as reg_key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(reg_key, i)  # Correct unpacking here
                        startup_entries.append(f"Startup: {name} -> {value}")
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            startup_entries.append(f"Key not found: {key}")
    return "\n".join(startup_entries)

def collect_usb_devices():
    """Collect USB device entries from the registry."""
    usb_devices = []
    usb_key = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, usb_key) as reg_key:
            i = 0
            while True:
                try:
                    device = winreg.EnumKey(reg_key, i)
                    usb_devices.append(f"USB Device: {device}")
                    i += 1
                except OSError:
                    break
    except FileNotFoundError:
        usb_devices.append("USBSTOR key not found")
    return "\n".join(usb_devices)

def collect_user_activity():
    """Collect user activity from the registry and return the output as a formatted string."""
    try:
        recent_docs_key = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
        user_activity = []

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, recent_docs_key) as reg_key:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(reg_key, i)
                    if isinstance(value, bytes):
                        try:
                            # Decode and clean the value
                            decoded_value = value.decode('utf-16-le', errors='ignore').strip()
                            # Keep only English letters and printable ASCII characters
                            cleaned_value = ''.join(c for c in decoded_value if c.isascii() and c.isprintable())
                        except UnicodeDecodeError:
                            cleaned_value = "[Decoding Error]"
                    else:
                        cleaned_value = ''.join(c for c in str(value).strip() if c.isascii() and c.isprintable())
                    
                    user_activity.append(f"Recent: {name} -> {cleaned_value}")
                    i += 1
                except OSError:
                    break

        # Return user activity as a formatted string
        return "\n".join(user_activity)

    except FileNotFoundError:
        return "RecentDocs registry key not found."
    except Exception as e:
        return f"Error analyzing user activity: {e}"
    
def collect_installed_software():
    """Collect installed software from the registry."""
    installed_software = []
    software_keys = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    ]
    for key in software_keys:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as reg_key:
                i = 0
                while True:
                    try:
                        sub_key_name = winreg.EnumKey(reg_key, i)
                        with winreg.OpenKey(reg_key, sub_key_name) as sub_key:
                            try:
                                display_name = winreg.QueryValueEx(sub_key, "DisplayName")[0]
                                installed_software.append(f"Installed Software: {display_name}")
                            except FileNotFoundError:
                                pass
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            installed_software.append(f"Key not found: {key}")
    return "\n".join(installed_software)
