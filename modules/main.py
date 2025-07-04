import os
from tkinter import Tk, filedialog, messagebox, Button, Label, Text, Entry, Frame, Scrollbar, Canvas, VERTICAL, ttk, END
from tkinter.scrolledtext import ScrolledText
from prefetch_files import start_prefetch_forensics

from file_analysis import find_hidden_files, calculate_file_hashes
from network_forensics import analyze_network_traffic, scan_open_ports_and_services
from disk_forensics import list_files
from browser_forensics import extract_edge_data
from event_logs import analyze_event_logs
from registry_forensics import collect_startup_entries, collect_usb_devices, collect_user_activity, collect_installed_software
from malware_forensics import collect_malware_artifacts
from shellbags_user_activity import extract_shellbag_data
import email_forensics 
from memory_forensics import scan_running_processes, list_dlls
from rdp_vpn_forensics import check_rdp_vpn
from sch_tasks import collect_scheduled_tasks  # Import the function for scheduled tasks



def select_directory():
    directory = filedialog.askdirectory(title="Select Directory")
    if not directory:
        messagebox.showerror("Error", "No directory selected!")
        return None
    return directory

def update_text_widget(widget, text):
    widget.delete(1.0, END)
    widget.insert(END, text)

# File Forensics
def analyze_files():
    directory = select_directory()
    if not directory:
        return
    
    hidden_files = find_hidden_files(directory)
    file_hashes = calculate_file_hashes(directory)

    hidden_files_text = "\n".join(hidden_files) if hidden_files else "No hidden files found."
    file_hashes_text = "\n".join([f"File: {file_hash['file']}\nMD5: {file_hash['md5']}\nSHA1: {file_hash['sha1']}\nSHA256: {file_hash['sha256']}\n" for file_hash in file_hashes])

    update_text_widget(hidden_files_output, hidden_files_text)
    update_text_widget(file_hashes_output, file_hashes_text)

# Network Forensics
def analyze_network_traffic_gui():
    pcap_file = filedialog.askopenfilename(title="Select PCAP File", filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")])
    if not pcap_file:
        messagebox.showerror("Error", "No PCAP file selected!")
        return
    
    result = analyze_network_traffic(pcap_file)
    update_text_widget(network_traffic_output, result)

def scan_ports_gui():
    target = port_scan_entry.get()
    if not target:
        messagebox.showerror("Error", "Please enter a target!")
        return
    
    result = scan_open_ports_and_services(target)
    update_text_widget(port_scan_output, result)

# Browser Forensics
def extract_edge_data_gui():
    browser_history_text.delete(1.0, END)
    browser_history_text.insert(END, "Extracting Edge Browser History...\n")
    app.update()
    history = extract_edge_data()
    update_text_widget(browser_history_text, "\n".join(history))

# Event Logs Forensics
def extract_event_logs_gui():
    event_logs = analyze_event_logs()
    update_text_widget(event_logs_output, event_logs if event_logs else "No event logs found or an error occurred.")

# Malware Forensics
def start_malware_forensics():
    output_dir = filedialog.askdirectory()
    if output_dir:
        collect_malware_artifacts(output_dir)
    else:
        messagebox.showerror("Error", "No directory selected.")

# Shellbag Forensics
def start_shellbag_forensics():
    shellbag_data = extract_shellbag_data()
    update_text_widget(shellbag_text, "\n".join(shellbag_data) if shellbag_data else "No shellbag data found.")

# Memory Forensics
def start_process_forensics():
    try:
        scan_running_processes()
    except Exception as e:
        messagebox.showerror("Process Forensics", f"An error occurred: {e}")

def start_dll_forensics():
    try:
        list_dlls()
    except Exception as e:
        messagebox.showerror("Memory Forensics", f"An error occurred: {e}")

# RDP/VPN Forensics
def start_rdp_vpn_forensics():
    output_text.delete(1.0, END)
    check_rdp_vpn(update_gui_callback)

def update_gui_callback(message):
    output_text.insert(END, message)
    output_text.yview(END)

# Registry Forensics Functions
def start_registry_forensics():
    """Start registry forensics and collect data."""
    startup_entries = collect_startup_entries()
    usb_devices = collect_usb_devices()
    user_activity = collect_user_activity()
    installed_software = collect_installed_software()

    # Update the respective text widgets with the collected data
    update_text_widget(startup_entries_output, startup_entries)
    update_text_widget(usb_devices_output, usb_devices)
    update_text_widget(user_activity_output, user_activity)
    update_text_widget(installed_software_output, installed_software)

# Disk Forensics Functions
def start_disk_forensics():
    """Start disk forensics and list files in the selected directory."""
    directory = filedialog.askdirectory()  # Open directory chooser dialog
    if not directory:
        update_text_widget(disk_forensics_output, "No directory selected.")
        return
    
    if not os.path.isdir(directory):
        update_text_widget(disk_forensics_output, "Invalid directory path.")
        return
    
    file_list = list_files(directory)
    if not file_list:
        update_text_widget(disk_forensics_output, "No files found in the directory.")
    else:
        file_info = "\n".join(
            [f"Name: {file['name']}, Type: {file['type']}, Modified: {file['modified']}, Accessed: {file['accessed']}, Created: {file['created']}" 
             for file in file_list]
        )
        update_text_widget(disk_forensics_output, file_info)

# Function to start email forensics
def start_email_forensics():
    """Start email forensics by selecting an mbox file."""
    mbox_file_path = filedialog.askopenfilename(title="Select .mbox File", filetypes=[("MBOX Files", "*.mbox")])
    
    if not mbox_file_path:
        messagebox.showerror("Error", "No .mbox file selected.")
        return
    
    # Call the function from the email_forensics module, not the tab
    result = email_forensics.process_email_forensics(mbox_file_path)
    
    # Display the result in a messagebox
    messagebox.showinfo("Result", "Result saved")

# Function to update the ScrolledText widget with the collected tasks
def update_scheduled_tasks_gui():
    try:
        scheduled_tasks = collect_scheduled_tasks()  # Get the list of scheduled tasks
        if scheduled_tasks:
            update_text_widget(scheduled_tasks_output, "\n".join(scheduled_tasks))
        else:
            update_text_widget(scheduled_tasks_output, "No scheduled tasks found.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to collect scheduled tasks: {e}")

# Update function for text widget
def update_text_widget(widget, text):
    widget.delete(1.0, END)
    widget.insert(END, text)

# Main GUI
app = Tk()
app.title("Digital Forensics Application")
app.geometry("900x700")

# Tab Control
tab_control = ttk.Notebook(app)
file_forensics_tab = Frame(tab_control)
network_forensics_tab = Frame(tab_control)
browser_forensics_tab = Frame(tab_control)
event_logs_tab = Frame(tab_control)
malware_forensics_tab = Frame(tab_control)
shellbag_forensics_tab = Frame(tab_control)
memory_forensics_tab = Frame(tab_control)
rdp_vpn_forensics_tab = Frame(tab_control)

tab_control.add(file_forensics_tab, text="File Forensics")
tab_control.add(network_forensics_tab, text="Network Forensics")
tab_control.add(browser_forensics_tab, text="Browser Forensics")
tab_control.add(event_logs_tab, text="Event Logs")
tab_control.add(malware_forensics_tab, text="Malware Forensics")
tab_control.add(shellbag_forensics_tab, text="Shellbag Forensics")
tab_control.add(memory_forensics_tab, text="Memory Forensics")
tab_control.add(rdp_vpn_forensics_tab, text="RDP/VPN Forensics")
tab_control.pack(expand=1, fill="both")

# File Forensics Tab
Label(file_forensics_tab, text="File Forensics", font=("Arial", 16)).pack(pady=10)
Button(file_forensics_tab, text="Analyze Files", command=analyze_files).pack(pady=10)

Label(file_forensics_tab, text="Hidden Files:").pack(anchor="w")
hidden_files_output = ScrolledText(file_forensics_tab, height=6, width=100)
hidden_files_output.pack(pady=10)

Label(file_forensics_tab, text="File Hashes:").pack(anchor="w")
file_hashes_output = ScrolledText(file_forensics_tab, height=6, width=100)
file_hashes_output.pack(pady=10)

# Network Forensics Tab
Label(network_forensics_tab, text="Network Forensics", font=("Arial", 16)).pack(pady=10)
Button(network_forensics_tab, text="Analyze Network Traffic", command=analyze_network_traffic_gui).pack(pady=10)
network_traffic_output = ScrolledText(network_forensics_tab, height=6, width=100)
network_traffic_output.pack(pady=10)

Label(network_forensics_tab, text="Port Scan Target:").pack(anchor="w")
port_scan_entry = Entry(network_forensics_tab, width=60)
port_scan_entry.pack(pady=5)
Button(network_forensics_tab, text="Scan Ports", command=scan_ports_gui).pack(pady=10)
port_scan_output = ScrolledText(network_forensics_tab, height=6, width=100)
port_scan_output.pack(pady=10)

# Browser Forensics Tab
Label(browser_forensics_tab, text="Browser Forensics", font=("Arial", 16)).pack(pady=10)
Button(browser_forensics_tab, text="Extract Edge Browser History", command=extract_edge_data_gui).pack(pady=10)
browser_history_text = ScrolledText(browser_forensics_tab, height=6, width=100)
browser_history_text.pack(pady=10)

# Event Logs Tab
Label(event_logs_tab, text="Event Logs Forensics", font=("Arial", 16)).pack(pady=10)
Button(event_logs_tab, text="Extract Event Logs", command=extract_event_logs_gui).pack(pady=10)
event_logs_output = ScrolledText(event_logs_tab, height=6, width=100)
event_logs_output.pack(pady=10)

# Malware Forensics Tab
Label(malware_forensics_tab, text="Malware Forensics", font=("Arial", 16)).pack(pady=10)
Button(malware_forensics_tab, text="Collect Malware Artifacts", command=start_malware_forensics).pack(pady=10)

# Shellbag Forensics Tab
Label(shellbag_forensics_tab, text="Shellbag Forensics", font=("Arial", 16)).pack(pady=10)
Button(shellbag_forensics_tab, text="Extract Shellbag Data", command=start_shellbag_forensics).pack(pady=10)
shellbag_text = ScrolledText(shellbag_forensics_tab, height=6, width=100)
shellbag_text.pack(pady=10)

# Memory Forensics Tab
Label(memory_forensics_tab, text="Memory Forensics", font=("Arial", 16)).pack(pady=10)
Button(memory_forensics_tab, text="Scan Running Processes", command=start_process_forensics).pack(pady=10)
Button(memory_forensics_tab, text="List DLLs", command=start_dll_forensics).pack(pady=10)

# RDP/VPN Forensics Tab
Label(rdp_vpn_forensics_tab, text="RDP/VPN Forensics", font=("Arial", 16)).pack(pady=10)
Button(rdp_vpn_forensics_tab, text="Check RDP/VPN", command=start_rdp_vpn_forensics).pack(pady=10)
output_text = ScrolledText(rdp_vpn_forensics_tab, height=6, width=100)
output_text.pack(pady=10)

# Add Registry Forensics Tab
registry_forensics_tab = Frame(tab_control)
tab_control.add(registry_forensics_tab, text="Registry Forensics")

# Registry Forensics Tab Layout
Label(registry_forensics_tab, text="Registry Forensics", font=("Arial", 16)).pack(pady=10)

Button(registry_forensics_tab, text="Start Registry Forensics", command=start_registry_forensics).pack(pady=10)

Label(registry_forensics_tab, text="Startup Entries:").pack(anchor="w")
startup_entries_output = ScrolledText(registry_forensics_tab, height=6, width=100)
startup_entries_output.pack(pady=10)

Label(registry_forensics_tab, text="USB Devices:").pack(anchor="w")
usb_devices_output = ScrolledText(registry_forensics_tab, height=6, width=100)
usb_devices_output.pack(pady=10)

Label(registry_forensics_tab, text="User Activity:").pack(anchor="w")
user_activity_output = ScrolledText(registry_forensics_tab, height=6, width=100)
user_activity_output.pack(pady=10)

Label(registry_forensics_tab, text="Installed Software:").pack(anchor="w")
installed_software_output = ScrolledText(registry_forensics_tab, height=6, width=100)
installed_software_output.pack(pady=10)

# Add Disk Forensics Tab
disk_forensics_tab = Frame(tab_control)
tab_control.add(disk_forensics_tab, text="Disk Forensics")

# Disk Forensics Tab Layout
Label(disk_forensics_tab, text="Disk Forensics", font=("Arial", 16)).pack(pady=10)

Label(disk_forensics_tab, text="Enter directory path to analyze:").pack(anchor="w")
directory_input = Entry(disk_forensics_tab, width=60)
directory_input.pack(pady=10)

Button(disk_forensics_tab, text="Start Disk Forensics", command=start_disk_forensics).pack(pady=10)

Label(disk_forensics_tab, text="File Information:").pack(anchor="w")
disk_forensics_output = ScrolledText(disk_forensics_tab, height=10, width=100)
disk_forensics_output.pack(pady=10)

# Add Email Forensics Tab
email_forensics_tab = Frame(tab_control)
tab_control.add(email_forensics_tab, text="Email Forensics")

# Email Forensics Tab Layout
Label(email_forensics_tab, text="Email Forensics", font=("Arial", 16)).pack(pady=10)
# Button to start email forensics
Button(email_forensics_tab, text="Start Email Forensics", command=start_email_forensics).pack(pady=10)

# Optional: To display the logs or output in the GUI (if needed)
Label(email_forensics_tab, text="Email Processing Log:").pack(anchor="w")
email_forensics_output = ScrolledText(email_forensics_tab, height=10, width=100)
email_forensics_output.pack(pady=10)

# Add a tab for Prefetch Forensics
prefetch_forensics_tab = Frame(tab_control)
tab_control.add(prefetch_forensics_tab, text="Prefetch Forensics")

# Prefetch Forensics Tab Layout
Label(prefetch_forensics_tab, text="Prefetch Forensics", font=("Arial", 16)).pack(pady=10)

# Button to start Prefetch Forensics
Button(prefetch_forensics_tab, text="Start Prefetch Forensics", 
           command=lambda: start_prefetch_forensics(prefetch_forensics_output)).pack(pady=10)

# Label for recently executed applications
Label(prefetch_forensics_tab, text="Recently Executed Applications:").pack(anchor="w")

# ScrolledText widget to display the output
prefetch_forensics_output = Text(prefetch_forensics_tab, height=10, width=100)
prefetch_forensics_output.pack(pady=10)

# Add a tab for Scheduled Tasks Forensics
scheduled_tasks_tab = Frame(tab_control)
tab_control.add(scheduled_tasks_tab, text="Scheduled Tasks Forensics")

# Scheduled Tasks Forensics Tab Layout
Label(scheduled_tasks_tab, text="Scheduled Tasks Forensics", font=("Arial", 16)).pack(pady=10)

# Button to start Scheduled Tasks Forensics
Button(scheduled_tasks_tab, text="Collect Scheduled Tasks", command=update_scheduled_tasks_gui).pack(pady=10)

# ScrolledText widget to display the collected scheduled tasks (optional, if you want to display them in the tab)
scheduled_tasks_output = ScrolledText(scheduled_tasks_tab, height=10, width=100)
scheduled_tasks_output.pack(pady=10)

app.mainloop()
