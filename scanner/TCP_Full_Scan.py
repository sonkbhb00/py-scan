import socket

def TCP_Full_Scan(target_ip, target_ports):
    
    open_ports = []
    for port in target_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()

    return open_ports

