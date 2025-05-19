from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.config import conf
import datetime
from collections import defaultdict
import platform
import socket
from colorama import Fore, Style, init

# Initialize colorama
init()

# Configuration
#conf.use_pcap = False
#conf.L3socket = conf.L3socket

# Initialize counters
protocol_counts = defaultdict(int)
ip_to_hostname = {}

# Color definitions
COLORS = {
    'TCP': Fore.GREEN,
    'UDP': Fore.BLUE,
    'ICMP': Fore.YELLOW,
    'Other': Fore.MAGENTA,
    'Reset': Style.RESET_ALL
}

def get_hostname(ip):
    """Try to resolve IP to hostname"""
    try:
        if ip not in ip_to_hostname:
            hostname = socket.gethostbyaddr(ip)[0]
            ip_to_hostname[ip] = hostname.split('.')[0]  # Take just the first part
        return ip_to_hostname[ip]
    except:
        return ip

def packet_callback(packet):
    """Process each captured packet"""
    try:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            # Try to get hostnames
            src_name = get_hostname(src_ip)
            dst_name = get_hostname(dst_ip)
            
            if packet.haslayer(TCP):
                protocol = "TCP"
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                protocol_counts["TCP"] += 1
                
                # Color-coded output
                print(f"{COLORS['TCP']}[{timestamp}] {protocol}: {src_name}:{src_port} → {dst_name}:{dst_port}{COLORS['Reset']}")
                
                # Detect HTTP/HTTPS
                if dst_port == 80:
                    print(f"    {Fore.CYAN}HTTP traffic detected{Style.RESET_ALL}")
                elif dst_port == 443:
                    print(f"    {Fore.CYAN}HTTPS traffic detected{Style.RESET_ALL}")
            
            elif packet.haslayer(UDP):
                protocol = "UDP"
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                protocol_counts["UDP"] += 1
                print(f"{COLORS['UDP']}[{timestamp}] {protocol}: {src_name}:{src_port} → {dst_name}:{dst_port}{COLORS['Reset']}")
                
                # Common UDP services
                if dst_port == 53 or src_port == 53:
                    print(f"    {Fore.CYAN}DNS traffic detected{Style.RESET_ALL}")
                elif dst_port == 5353:
                    print(f"    {Fore.CYAN}mDNS (Bonjour) traffic detected{Style.RESET_ALL}")
            
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
                protocol_counts["ICMP"] += 1
                print(f"{COLORS['ICMP']}[{timestamp}] {protocol}: {src_name} → {dst_name}{COLORS['Reset']}")
            
            else:
                protocol = "Other-IP"
                protocol_counts["Other-IP"] += 1
                print(f"{COLORS['Other']}[{timestamp}] {protocol}: {src_name} → {dst_name}{COLORS['Reset']}")
        
        # Print summary every 20 packets
        if sum(protocol_counts.values()) % 20 == 0:
            print(f"\n{Fore.WHITE}{Style.BRIGHT}--- Traffic Summary ---{Style.RESET_ALL}")
            total = sum(protocol_counts.values())
            for proto, count in sorted(protocol_counts.items()):
                percent = (count / total) * 100
                print(f"{COLORS.get(proto.split('-')[0], Fore.WHITE)}{proto}: {count} packets ({percent:.1f}%){COLORS['Reset']}")
            print(f"{Fore.WHITE}{Style.BRIGHT}----------------------{Style.RESET_ALL}\n")
    
    except Exception as e:
        print(f"{Fore.RED}Error processing packet: {e}{Style.RESET_ALL}")

def start_sniffing():
    """Start the packet sniffing process"""
    print(f"\n{Fore.YELLOW}Starting Advanced Network Sniffer...{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Press Ctrl+C to stop{Style.RESET_ALL}\n")
    
    try:
        sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Sniffer stopped by user.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    start_sniffing()