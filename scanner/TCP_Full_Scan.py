import socket
import time
from utils.decoratives import decor
def TCP_Full_Scan(target_ip, target_ports):
    
    open_ports = []
    scanned_ports = 0
    for port in target_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        response = sock.connect_ex((target_ip, port))
        if response == 0:
            open_ports.append(port)
        sock.close()
        scanned_ports = scanned_ports + 1
        decor(len(target_ports), scanned_ports)

    return open_ports

