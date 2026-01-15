import argparse
import socket
import threading

from scanner import TCP_Full_Scan, SYN_Stealth_Scan


def main():
    parser = argparse.ArgumentParser()
    
    parser.add_argument("target", help="Target IP address or hostname to scan.")
    
    # Group for scan types
    scan_group = parser.add_mutually_exclusive_group()
    scan_group.add_argument("-sT", action="store_true", help="TCP Connect scan (default)")
    scan_group.add_argument("-sS", action="store_true", help="SYN Stealth scan")
    scan_group.add_argument("-sA", action="store_true", help="ACK scan")
    scan_group.add_argument("-sN", action="store_true", help="Null scan")
    scan_group.add_argument("-sX", action="store_true", help="Xmas scan")
    
    parser.add_argument("-p", "--ports", help="Comma-separated list of ports to scan.", default=None)
    parser.add_argument("-t", "--threads", help="Number of threads to use for scanning.", type=int, default=10)
    
    args = parser.parse_args()
    
    if not any([args.sT, args.sS, args.sA, args.sN, args.sX]):
        args.sT = True  # Default to TCP Connect scan if no scan type is specified.
    
    # Resolve hostname to IP if necessary
    try:
        args.target = socket.gethostbyname(args.target) 
    except socket.gaierror:
        print(f"Error: Cannot resolve hostname '{args.target}'")
        return
    
    
    if args.ports: 
        ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]
    else: 
        ports = ports_to_scan()
    
    print(f"Scanning {args.target} on {len(ports)} ports...")
    print(f"Mode: {'TCP Connect Scan' if args.sT else 'SYN Stealth Scan' if args.sS else 'Other Scan Type'}")
    
    if args.sT:
        open_ports = TCP_Full_Scan(args.target, ports)
    elif args.sS:
        open_ports = SYN_Stealth_Scan(args.target, ports)
    
    print(f"\nScan complete!")
    print(f"Open ports: {open_ports if open_ports else 'None'}")


def ports_to_scan():
    with open('1000-Common-Ports.txt', 'r') as f:
        return [int(line.strip()) for line in f.readlines() if line.strip().isdigit()]

def domain_to_ip(domain):
    return socket.gethostbyname(domain)



if __name__ == "__main__":
    main()
    