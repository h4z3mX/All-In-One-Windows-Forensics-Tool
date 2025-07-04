# rdp_vpn_forensics.py
import subprocess
import re
import psutil

# Function to check for RDP (Remote Desktop Protocol) connections
def check_rdp_connections(update_gui_callback):
    update_gui_callback("Checking for RDP connections...\n")

    # Use netstat to find active connections on port 3389 (default RDP port)
    try:
        result = subprocess.run(['netstat', '-an'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        rdp_connections = []
        for line in result.stdout.splitlines():
            if re.search(r':3389\s+.*\s+ESTABLISHED', line):  # Look for ESTABLISHED connections on port 3389
                rdp_connections.append(line)

        if rdp_connections:
            update_gui_callback("Found RDP connections:\n")
            for conn in rdp_connections:
                update_gui_callback(f"{conn}\n")
        else:
            update_gui_callback("No RDP connections found.\n")
    except Exception as e:
        update_gui_callback(f"Error checking for RDP connections: {e}\n")

# Function to check for active VPN connections
def check_vpn_connections(update_gui_callback):
    update_gui_callback("Checking for VPN connections...\n")

    # Using psutil to find network adapters that might be used by VPN software
    vpn_connections = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            # Check if the process is a known VPN software (example: OpenVPN, Cisco AnyConnect, etc.)
            if 'vpn' in proc.info['name'].lower() or 'openvpn' in proc.info['name'].lower():
                vpn_connections.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    # You can also check if any VPN adapter is up by checking the network interfaces
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            # Check for VPN adapter (e.g., TUN, TAP interfaces, or specific adapter names)
            if 'vpn' in interface.lower() or 'tun' in interface.lower():
                vpn_connections.append({'interface': interface, 'ip': addr.address})

    if vpn_connections:
        update_gui_callback("Found VPN connections:\n")
        for conn in vpn_connections:
            if isinstance(conn, dict):  # Network adapter (interface) connection
                update_gui_callback(f"VPN Adapter {conn['interface']} - IP: {conn['ip']}\n")
            else:  # Process-based connection
                update_gui_callback(f"VPN Process {conn['name']} (PID: {conn['pid']}) - Command line: {' '.join(conn['cmdline'])}\n")
    else:
        update_gui_callback("No VPN connections found.\n")

# Main function to check both RDP and VPN connections
def check_rdp_vpn(update_gui_callback):
    check_rdp_connections(update_gui_callback)
    check_vpn_connections(update_gui_callback)
