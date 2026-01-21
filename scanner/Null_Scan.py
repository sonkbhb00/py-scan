import scapy.all as scapy
from utils.decoratives import decor

def Null_Scan(target_ip, target_ports):
    closed_ports = []
    open_or_filtered_ports = []
    filtered_ports = []  # ICMP unreachable
    scanned_port = 0
    
    for port in target_ports:
        packet = scapy.IP(dst=target_ip)/scapy.TCP(dport=port, flags="")
        response = scapy.sr1(packet, timeout=1, verbose=0)
        
        if response is None:
            # No response = open|filtered
            open_or_filtered_ports.append(port)
        elif response.haslayer(scapy.TCP):
            if response.getlayer(scapy.TCP).flags == 0x14:  # RST+ACK or RST
                closed_ports.append(port)
        elif response.haslayer(scapy.ICMP):
            # ICMP unreachable = filtered
            filtered_ports.append(port)
        else:
            open_or_filtered_ports.append(port)
            
        scanned_port += 1
        decor(len(target_ports), scanned_port)
        
    return closed_ports, open_or_filtered_ports, filtered_ports
