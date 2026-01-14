import argparse
import socket
import threading
from scanner import TCP_Full_Scan, SYN_Stealth_Scan

def main():
    parser = argparse.ArgumentParser(description="A port scanner.")
    
    parser.add_argument("-m", "--mode", help="Scan mode Connect, Syn, Ack, Null, Xmas.", choices=["Connect", "Syn", "Ack", "Null", "Xmas"], default="Connect")
    parser.add_argument("target", help="Target IP address or hostname to scan.")
    parser.add_argument("-p", "--ports", help="Comma-separated list of ports to scan.", default=None)
    parser.add_argument("-t", "--threads", help="Number of threads to use for scanning.", type=int, default=10)
    
    args = parser.parse_args()
    
    if args.target.replace('.', '').isdigit():
        args.target = args.target
    else:
        args.target = domain_to_ip(args.target)
    
    
    if args.ports: 
        ports = [int(p.strip()) for p in args.ports.split(",") if p.strip().isdigit()]
    else: 
        ports = ports_to_scan()
    
    print(f"Scanning {args.target} on {len(ports)} ports...")
    print(f"Mode: {args.mode}")
    
    if args.mode == "Connect":
        open_ports = TCP_Full_Scan(args.target, ports)
    elif args.mode == "Syn":
        open_ports = SYN_Stealth_Scan(args.target, ports)
    else:
        print(f"Mode {args.mode} is not implemented yet.")
        return
    
    print(f"\nScan complete!")
    print(f"Open ports: {open_ports if open_ports else 'None'}")


def ports_to_scan():
    with open('1000-Common-Ports.txt', 'r') as f:
        return [int(line.strip()) for line in f.readlines() if line.strip().isdigit()]

def domain_to_ip(domain):
    return socket.gethostbyname(domain)



if __name__ == "__main__":
    main()