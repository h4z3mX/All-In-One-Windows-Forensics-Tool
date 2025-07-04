# even_logs.py

import subprocess

def scan_event_logs():
    """Scan and save system event logs."""
    try:
        # Run the wevtutil command to export logs to a file
        output_file = "event_logs.txt"
        wevtutil_cmd = ["wevtutil", "epl", "System", output_file]
        subprocess.run(wevtutil_cmd, check=True)
        return f"Event logs saved to {output_file}."
    except FileNotFoundError:
        return "wevtutil is not installed or not found in PATH."
    except Exception as e:
        return f"Error scanning event logs: {e}"

def analyze_event_logs():
    """Analyze system event logs and return the analysis as a string."""
    try:
        # Run the wevtutil command to query the event logs
        output_file = "event_logs_analysis.txt"
        wevtutil_cmd = ["wevtutil", "qe", "System", "/f:text"]
        
        # Capture the output
        result = subprocess.run(wevtutil_cmd, capture_output=True, text=True, check=True)

        # Return the output as a string to be displayed in the GUI
        return result.stdout

    except FileNotFoundError:
        return "wevtutil is not installed or not found in PATH."
    except Exception as e:
        return f"Error analyzing event logs: {e}"
