# memory_forensics.py
import subprocess
from tkinter import messagebox

def scan_running_processes():
    try:
        output_file = "running_processes.txt"
        tasklist_cmd = ["tasklist", "/v", "/fo", "csv"]
        with open(output_file, "w") as f:
            subprocess.run(tasklist_cmd, stdout=f, check=True)

        messagebox.showinfo("Process Forensics", f"Running processes saved to {output_file}.")
    except Exception as e:
        messagebox.showerror("Process Forensics", f"Error scanning running processes: {e}")


def list_dlls():
    try:
        output_file = "loaded_dlls.txt"
        tasklist_cmd = ["tasklist", "/m", "/fo", "csv"]
        with open(output_file, "w") as f:
            subprocess.run(tasklist_cmd, stdout=f, check=True)

        messagebox.showinfo("Memory Forensics", f"Loaded DLLs saved to {output_file}.")
    except Exception as e:
        messagebox.showerror("Memory Forensics", f"Error listing loaded DLLs: {e}")
