import argparse
import socket
import threading
def main():
    parser = argparse.ArgumentParser(description="A port scanner.")
    
    parser.add_argument("-m", "--mode", help="Scan mode Connect, Syn, Ack, Null, Xmas.", choices=["Connect", "Syn", "Ack", "Null", "Xmas"], default="Connect")
    parser.add_argument("target", help="Target IP address or hostname to scan.")
    parser.add_argument("-p", "--ports", help="Comma-separated list of ports to scan.", default=ports_to_scan())
    parser.add_argument("-thead", "--threads", help="Number of threads to use for scanning.", type=int, default=10)

def ports_to_scan():
    with open('1000-Common-Ports.txt', 'r') as f:
        return f.readlines()

def domain_to_ip(domain):
    return socket.gethostbyname(domain)

if __name__ == "__main__":
    main()