import os
import subprocess

def analyze_network_traffic(pcap_file):
    """
    Analyze network traffic from a PCAP file using Tshark.
    :param pcap_file: Path to the PCAP file.
    """
    try:
        output_file = f"{os.path.splitext(pcap_file)[0]}_analysis.txt"
        tshark_cmd = [
            "tshark",
            "-r", pcap_file,
            "-q",
            "-z", "io,stat,1"
        ]
        with open(output_file, "w") as f:
            subprocess.run(tshark_cmd, stdout=f, check=True)
        return f"Network traffic analysis saved to {output_file}."
    except FileNotFoundError:
        return "Error: Tshark is not installed or not found in PATH."
    except Exception as e:
        return f"Error analyzing network traffic: {e}"

def scan_open_ports_and_services(target):
    """
    Scan for open ports and services using nmap.
    :param target: The target IP or hostname.
    """
    try:
        output_file = f"{target}_nmap_scan.txt"
        nmap_cmd = ["nmap", "-sV", target]
        with open(output_file, "w") as f:
            subprocess.run(nmap_cmd, stdout=f, check=True)
        return f"Nmap scan results saved to {output_file}."
    except FileNotFoundError:
        return "Error: Nmap is not installed or not found in PATH."
    except Exception as e:
        return f"Error running Nmap scan: {e}"
