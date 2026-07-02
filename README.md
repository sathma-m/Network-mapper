Network Mapper

A Python tool that discovers live hosts on a local network via ARP scanning, port-scans each one for open services, and visualizes the results as both a terminal tree and a graph image.
Built as a follow-up to a single-host TCP port scanner - this project extends that into full local network discovery and mapping.

⚠️ Use responsibly. Only run this against networks and devices you own or have explicit permission to scan. ARP scanning your own home/office LAN is fine - scanning networks you don't control is not.


## Features

* Host Discovery - Uses ARP requests (via scapy) to find every live device on the local subnet, more reliable than a ping sweep since ARP can't be blocked by host-level firewalls.
* Service Detection - Port-scans each discovered host and attempts banner grabbing to identify running services.
* Concurrent Scanning - Uses ThreadPoolExecutor to scan multiple ports per host simultaneously.
* Terminal Visualization - Prints a clean tree view of the network straight to the console.
* Graph Visualization - Generates a network diagram image (network_map.png) using networkx + matplotlib.
* Automated Logging - Saves all findings to network_map.txt.


## Example Output 

Terminal Tree :
<img width="437" height="366" alt="Screenshot 2026-07-02 174300" src="https://github.com/user-attachments/assets/85a499a2-c800-4f68-af1f-d59ff58dc74b" />

Graph image :
<img width="1295" height="870" alt="Screenshot 2026-07-02 180131" src="https://github.com/user-attachments/assets/844c50ef-075a-447b-b541-1f3a4b2c71df" />

## Requirements

* Python 3.8+
* Npcap (Windows only) - required for scapy to send/receive raw packets. Install with "WinPcap API-compatible mode" checked.
* Administrator / root privileges - raw ARP packets require elevated access.


Install Python dependencies:
bashpip install -r requirements.txt

## Usage

Run as Administrator (Windows) or with sudo (Linux/macOS):
python network_mapper.py 192.168.1.0/24

Or run it with no arguments and enter the subnet when prompted:
python network_mapper.py

Find your own subnet first:
Windows: ipconfig → look for your active adapter's IPv4 Address
Linux/macOS: ip a or ifconfig
Your subnet is the same first three numbers as your IP, e.g. if your IP is 192.168.1.23, scan 192.168.1.0/24

## How It Works

*ARP Scan - Broadcasts an ARP "who has this IP?" request to every address in the subnet. Every live device on the network has to respond at this layer, so this reliably discovers hosts that might otherwise ignore a ping.
*Port Scan - Each discovered host is scanned against a list of common ports using multi-threaded TCP connections, with banner grabbing to identify the service running.
*Output - Results are printed as a terminal tree, saved to a text log, and rendered as a graph image (subnet → hosts → open ports).

## Skills Demonstrated

*Networking fundamentals: ARP, TCP handshakes, the socket and scapy libraries
*Concurrency: multi-threaded scanning with ThreadPoolExecutor
*Data visualization: graph construction and rendering with networkx / matplotlib
*Error handling: managing timeouts, permission issues, and connection failures gracefully
*Tool design: CLI interface, structured logging, modular code

## Disclaimer

This tool is intended for educational purposes and authorized network administration/security testing only. The author is not responsible for misuse. Always obtain proper authorization before scanning any network you do not own.

