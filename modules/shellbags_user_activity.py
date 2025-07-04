# shellbags_user_activity.py
import winreg

def extract_shellbag_data():
    shellbag_key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
    
    shellbag_data = []
    try:
        # Open the Registry key
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, shellbag_key_path) as key:
            # Iterate through all the subkeys and values
            index = 0
            while True:
                try:
                    value_name, value_data, value_type = winreg.EnumValue(key, index)
                    if value_type == winreg.REG_SZ or value_type == winreg.REG_EXPAND_SZ:
                        shellbag_data.append(f"Shellbag Key: {value_name}, Path: {value_data}")
                    index += 1
                except OSError:
                    break
    except FileNotFoundError:
        shellbag_data.append(f"Registry key {shellbag_key_path} not found.")
    
    return shellbag_data
