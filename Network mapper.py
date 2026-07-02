import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from scapy.all import ARP, Ether, srp , conf
import networkx as nx
import matplotlib.pyplot as plt
conf.iface = "Wi-Fi"




# STAGE 1 : Host discovery via ARP scan

def arp_scan(subnet):
   
    print(f"[*] ARP scanning {subnet} ... (this needs root/admin privileges)")

    arp_request = ARP(pdst=subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    # timeout=2 -> wait 2s for replies. verbose=False keeps scapy quiet.
    answered, _ = srp(packet, timeout=2, verbose=False)

    hosts = []
    for sent, received in answered:
        hosts.append({"ip": received.psrc, "mac": received.hwsrc})

    return hosts



# STAGE 2 : Port scanning each discovered host (same idea as your original tool)

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080]


def scan_port(ip, port, results, timeout=0.7):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) == 0:
            banner = "Unknown"
            try:
                s.send(b"Hello\n")
                banner = s.recv(1024).decode(errors="ignore").strip() or "No banner"
            except Exception:
                pass
            results.append({"port": port, "banner": banner})
        s.close()
    except Exception:
        pass


def scan_host(ip, ports=COMMON_PORTS, max_threads=50):
    results = []
    with ThreadPoolExecutor(max_threads) as pool:
        for port in ports:
            pool.submit(scan_port, ip, port, results)
    return sorted(results, key=lambda r: r["port"])



# STAGE 3a : Terminal tree output

def print_tree(network_map, subnet):
    print(f"\n{subnet}")
    for i, host in enumerate(network_map):
        is_last_host = i == len(network_map) - 1
        branch = "└──" if is_last_host else "├──"
        print(f"{branch} {host['ip']}  ({host['mac']})")
        prefix = "    " if is_last_host else "│   "
        if not host["open_ports"]:
            print(f"{prefix}└── no open ports found (from common port list)")
        for j, p in enumerate(host["open_ports"]):
            is_last_port = j == len(host["open_ports"]) - 1
            pbranch = "└──" if is_last_port else "├──"
            print(f"{prefix}{pbranch} {p['port']}/tcp  {p['banner']}")



# STAGE 3b : Graph image via networkx + matplotlib

def draw_graph(network_map, subnet, outfile="network_map.png"):
    G = nx.Graph()
    center = subnet
    G.add_node(center, kind="network")

    for host in network_map:
        label = f"{host['ip']}\n{host['mac']}"
        G.add_node(label, kind="host")
        G.add_edge(center, label)

        for p in host["open_ports"]:
            port_label = f"{host['ip']}:{p['port']}\n{p['banner'][:20]}"
            G.add_node(port_label, kind="port")
            G.add_edge(label, port_label)

    colors = []
    sizes = []
    for node, data in G.nodes(data=True):
        kind = data.get("kind")
        if kind == "network":
            colors.append("#333333")
            sizes.append(1200)
        elif kind == "host":
            colors.append("#4C72B0")
            sizes.append(900)
        else:
            colors.append("#DD8452")
            sizes.append(500)

    plt.figure(figsize=(12, 8))
    pos = nx.spring_layout(G, k=0.9, seed=42)
    nx.draw(
        G, pos,
        with_labels=True,
        node_color=colors,
        node_size=sizes,
        font_size=7,
        edge_color="#999999",
    )
    plt.title(f"Network Map: {subnet}")
    plt.tight_layout()
    plt.savefig(outfile, dpi=150)
    print(f"[!] Graph saved to {outfile}")



# STAGE 4: Logging

def save_log(network_map, subnet, outfile="network_map.txt"):
    with open(outfile, "w") as f:
        f.write(f"Network map for {subnet}\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 40 + "\n\n")
        for host in network_map:
            f.write(f"Host: {host['ip']} ({host['mac']})\n")
            if not host["open_ports"]:
                f.write("  No open ports found\n")
            for p in host["open_ports"]:
                f.write(f"  Port {p['port']}: {p['banner']}\n")
            f.write("\n")
    print(f"[!] Text log saved to {outfile}")



# Main

def main():
    if len(sys.argv) > 1:
        subnet = sys.argv[1]
    else:
        subnet = input("Subnet to scan (e.g. 192.168.1.0/24): ").strip()

    live_hosts = arp_scan(subnet)
    print(f"[*] Found {len(live_hosts)} live host(s). Port-scanning each...\n")

    network_map = []
    for host in live_hosts:
        print(f"    -> scanning {host['ip']} ...")
        open_ports = scan_host(host["ip"])
        network_map.append({**host, "open_ports": open_ports})

    print_tree(network_map, subnet)
    save_log(network_map, subnet)
    draw_graph(network_map, subnet)


if __name__ == "__main__":
    main()