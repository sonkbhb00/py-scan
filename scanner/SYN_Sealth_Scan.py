import scapy.all as scapy

def SYN_Stealth_Scan(target_ip, target_ports):
    open_ports = []
    for port in target_ports:
        packet = scapy.IP(dst=target_ip)/scapy.TCP(dport=port, flags="S")
        response = scapy.sr1(packet, timeout=1, verbose=0)
        
        if response and response.haslayer(scapy.TCP):
            if response.getlayer(scapy.TCP).flags == 0x12:  # SYN-ACK
                open_ports.append(port)
                # Send RST to close the connection
                rst_packet = scapy.IP(dst=target_ip)/scapy.TCP(dport=port, flags="R")
                scapy.send(rst_packet, verbose=0)

    return open_ports