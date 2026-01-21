import argparse
import os
import socket
import time

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
    parser.add_argument("-sV", "--version", action="store_true", help="Version detection - probe open ports to determine service/version info")
    
    # Timing templates (like Nmap)
    timing_group = parser.add_mutually_exclusive_group()
    timing_group.add_argument("-T0", action="store_const", const=0, dest="timing", help="Paranoid (serial, 5min timeout) - IDS evasion")
    timing_group.add_argument("-T1", action="store_const", const=1, dest="timing", help="Sneaky (serial, 15s timeout) - IDS evasion")
    timing_group.add_argument("-T2", action="store_const", const=2, dest="timing", help="Polite (serial, 1s timeout) - Less bandwidth")
    timing_group.add_argument("-T3", action="store_const", const=3, dest="timing", help="Normal (parallel, 1s timeout) - Default")
    timing_group.add_argument("-T4", action="store_const", const=4, dest="timing", help="Aggressive (parallel, 0.5s timeout) - Fast scan")
    timing_group.add_argument("-T5", action="store_const", const=5, dest="timing", help="Insane (parallel, 0.3s timeout) - Very fast")
    
    # Manual overrides
    parser.add_argument("--max-delay", type=float, help="Max delay between probes (seconds)", default=None)
    parser.add_argument("--timeout", type=float, help="Timeout for connections (seconds)", default=None)
    
    args = parser.parse_args()
    
    # Set default timing to T3 (Normal)
    if args.timing is None:
        args.timing = 3
    
    # Configure timing parameters based on template
    timing_configs = {
        0: {"parallel": False, "timeout": 300, "delay": 5.0, "name": "Paranoid (T0)"},
        1: {"parallel": False, "timeout": 15, "delay": 1.5, "name": "Sneaky (T1)"},
        2: {"parallel": False, "timeout": 2.5, "delay": 0.4, "name": "Polite (T2)"},
        3: {"parallel": True, "timeout": 1.0, "delay": 0, "name": "Normal (T3)"},
        4: {"parallel": True, "timeout": 0.5, "delay": 0, "name": "Aggressive (T4)"},
        5: {"parallel": True, "timeout": 0.3, "delay": 0, "name": "Insane (T5)"},
    }
    
    config = timing_configs[args.timing]
    
    # Apply manual overrides
    if args.timeout is not None:
        config["timeout"] = args.timeout
    if args.max_delay is not None:
        config["delay"] = args.max_delay
    
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
    print(f"Timing: {config['name']} (timeout: {config['timeout']}s, delay: {config['delay']}s)")
    print()
    
    if args.sT:
        start_time = time.time()
        open_ports = TCP_Full_Scan(args.target, ports, timeout=config['timeout'], delay=config['delay'], parallel=config['parallel'])
        elapsed_time = time.time() - start_time
        print(f"\nScan complete!")
        print(f"Open ports ({len(open_ports) if open_ports else 0}): {open_ports if open_ports else 'None'}")
        print(f"Scan duration: {elapsed_time:.2f}s")
        if args.version and open_ports:
            print_banners(args.target, open_ports)
    elif args.sS:
        start_time = time.time()
        open_ports = SYN_Stealth_Scan(args.target, ports, timeout=config['timeout'], delay=config['delay'], parallel=config['parallel'])
        elapsed_time = time.time() - start_time
        print(f"\nScan complete!")
        print(f"Open ports ({len(open_ports) if open_ports else 0}): {open_ports if open_ports else 'None'}")
        print(f"Scan duration: {elapsed_time:.2f}s")
        if args.version and open_ports:
            print_banners(args.target, open_ports)
    elif args.sA:
        start_time = time.time()
        unfiltered_ports, filtered_ports = Ack_Full_Scan(args.target, ports, timeout=config['timeout'], delay=config['delay'], parallel=config['parallel'])
        elapsed_time = time.time() - start_time
        print(f"\nScan complete!")
        print(f"Unfiltered ports ({len(unfiltered_ports) if unfiltered_ports else 0}): {unfiltered_ports if unfiltered_ports else 'None'}")
        print(f"Filtered ports ({len(filtered_ports) if filtered_ports else 0}): {filtered_ports if filtered_ports else 'None'}")
        print(f"Scan duration: {elapsed_time:.2f}s")
    elif args.sX:
        start_time = time.time()
        closed_ports, open_filtered_ports = Xmas_Scan(args.target, ports, timeout=config['timeout'], delay=config['delay'], parallel=config['parallel'])
        elapsed_time = time.time() - start_time
        print(f"\nScan complete!")
        print(f"Closed ports ({len(closed_ports) if closed_ports else 0}): {closed_ports if closed_ports else 'None'}")
        print(f"Open|Filtered ports ({len(open_filtered_ports) if open_filtered_ports else 0}): {open_filtered_ports if open_filtered_ports else 'None'}")
        print(f"Scan duration: {elapsed_time:.2f}s")
    elif args.sN:
        start_time = time.time()
        closed_ports, open_filtered_ports, filtered_ports = Null_Scan(args.target, ports, timeout=config['timeout'], delay=config['delay'], parallel=config['parallel'])
        elapsed_time = time.time() - start_time
        print(f"\nScan complete!")
        print(f"Closed ports ({len(closed_ports) if closed_ports else 0}): {closed_ports if closed_ports else 'None'}")
        print(f"Open|Filtered ports ({len(open_filtered_ports) if open_filtered_ports else 0}): {open_filtered_ports if open_filtered_ports else 'None'}")
        print(f"Filtered ports ({len(filtered_ports) if filtered_ports else 0}): {filtered_ports if filtered_ports else 'None'}")
        print(f"Scan duration: {elapsed_time:.2f}s")

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
