import argparse
import os
import socket

from scanner import TCP_Full_Scan, SYN_Stealth_Scan, Ack_Full_Scan, Xmas_Scan, Null_Scan
from utils.banner_grapping import grab_banners


def main():
    parser = argparse.ArgumentParser()
    
    parser.add_argument("target", help="Target IP address or hostname to scan.")
    
    # Group for scan types
    scan_group = parser.add_mutually_exclusive_group()
    scan_group.add_argument("-sT", action="store_true", help="TCP Connect scan (default)")
    scan_group.add_argument("-sS", action="store_true", help="SYN Stealth scan")
    scan_group.add_argument("-sA", action="store_true", help="ACK scan")
    scan_group.add_argument("-sN", action="store_true", help="Null scan (only for Linux )")
    scan_group.add_argument("-sX", action="store_true", help="Xmas scan")
    
    parser.add_argument("-p", "--ports", help="Comma-separated list of ports to scan.", default=None)
    parser.add_argument("-t", "--threads", help="Number of threads to use for scanning.", type=int, default=10)
    parser.add_argument("-sV", "--version", action="store_true", help="Version detection - probe open ports to determine service/version info")
    
    args = parser.parse_args()
    
    if not any([args.sT, args.sS, args.sA, args.sN, args.sX]):
        args.sT = True  # Default to TCP Connect scan if no scan type is specified.
    
    # Resolve hostname to IP if necessary
    try:
        args.target = domain_to_ip(args.target)
    except socket.gaierror:
        print(f"Error: Cannot resolve hostname '{args.target}'")
        return
    
    
    if args.ports: 
        ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]
    else: 
        ports = ports_to_scan()
    
    print(f"Scanning {args.target} on {len(ports)} ports...")
    print(f"Mode: {'TCP Connect Scan' if args.sT else \
          'SYN Stealth Scan' if args.sS else \
          'ACK Scan' if args.sA else \
          'Null Scan' if args.sN else \
          'Xmas Scan'}")
    
    if args.sT:
        open_ports = TCP_Full_Scan(args.target, ports)
        print(f"\nScan complete!")
        print(f"Open ports: {open_ports if open_ports else 'None'}")
        if args.version and open_ports:
            print_banners(args.target, open_ports)
    elif args.sS:
        open_ports = SYN_Stealth_Scan(args.target, ports)
        print(f"\nScan complete!")
        print(f"Open ports: {open_ports if open_ports else 'None'}")
        if args.version and open_ports:
            print_banners(args.target, open_ports)
    elif args.sA:
        unfiltered_ports, filtered_ports = Ack_Full_Scan(args.target, ports)
        print(f"\nScan complete!")
        print(f"Unfiltered ports: {unfiltered_ports if unfiltered_ports else 'None'}")
        print(f"Filtered ports: {filtered_ports if filtered_ports else 'None'}")
    elif args.sX:
        closed_ports, open_filtered_ports = Xmas_Scan(args.target, ports)
        print(f"\nScan complete!")
        print(f"Closed ports: {closed_ports if closed_ports else 'None'}")
        print(f"Open|Filtered ports: {open_filtered_ports if open_filtered_ports else 'None'}")
    elif args.sN:
        closed_ports, open_filtered_ports, filtered_ports = Null_Scan(args.target, ports)
        print(f"\nScan complete!")
        print(f"Closed ports: {closed_ports if closed_ports else 'None'}")
        print(f"Open|Filtered ports: {open_filtered_ports if open_filtered_ports else 'None'}")
        print(f"Filtered ports: {filtered_ports if filtered_ports else 'None'}")

def print_banners(target, open_ports):
    print("\n[Version Detection - Banner Grabbing]")
    banners = grab_banners(target, open_ports)
    if banners:
        for port, banner in banners.items():
            first_line = banner.split('\n')[0][:100]
            print(f"  Port {port}: {first_line}")
    else:
        print("  No banners retrieved.")


def ports_to_scan():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, '1000-Common-Ports.txt')
    with open(file_path, 'r') as f:
        return [int(line.strip()) for line in f.readlines() if line.strip().isdigit()]

def domain_to_ip(domain):
    return socket.gethostbyname(domain)



if __name__ == "__main__":
    main()
