from scapy.all import sniff, IP, TCP, UDP, conf

print("🛡️ Basic Firewall Using Python")
print("----------------------------------")

# Get user-defined rules
blocked_ips = input("Enter IP addresses to block (comma-separated, or leave blank for none): ").strip()
blocked_ports = input("Enter ports to block (comma-separated, or leave blank for none): ").strip()

# Convert user input into lists
blocked_ips = [ip.strip() for ip in blocked_ips.split(",") if ip.strip()]
blocked_ports = [int(port.strip()) for port in blocked_ports.split(",") if port.strip()]

print("\n✅ Firewall Rules Set")
print(f"Blocked IPs: {blocked_ips if blocked_ips else 'None'}")
print(f"Blocked Ports: {blocked_ports if blocked_ports else 'None'}")
print("\n🔍 Monitoring network packets... (Press Ctrl+C to stop)\n")

# Define packet filtering logic
def packet_filter(packet):
    if packet.haslayer(IP):  # Layer 3: IP
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Check for blocked IPs
        if src_ip in blocked_ips or dst_ip in blocked_ips:
            print(f"🚫 Blocked packet (IP rule): {src_ip} → {dst_ip}")
            return

        # Check for blocked ports (Layer 4: TCP/UDP)
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            if sport in blocked_ports or dport in blocked_ports:
                print(f"🚫 Blocked packet (Port rule): {src_ip}:{sport} → {dst_ip}:{dport}")
                return
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            if sport in blocked_ports or dport in blocked_ports:
                print(f"🚫 Blocked packet (Port rule): {src_ip}:{sport} → {dst_ip}:{dport}")
                return

        # If not blocked
        print(f"✅ Allowed packet: {src_ip} → {dst_ip}")

try:
    sniff(opened_socket=conf.L3socket(), prn=packet_filter, store=0)
except KeyboardInterrupt:
    print("\n🛑 Firewall stopped by user.")
except PermissionError:
    print("\n⚠️ Please run VS Code as Administrator for full packet access.")
except Exception as e:
    print(f"\n⚠️ Error: {e}")





