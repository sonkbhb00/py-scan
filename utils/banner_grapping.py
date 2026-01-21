import socket
import ssl

def try_probe():
    return b"HEAD / HTTP/1.0\r\n\r\n"

def grab_banner(ip_address, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((ip_address, port))
        
        banner = b""
        
        try:
            
            banner = s.recv(1024)
            
        except socket.timeout:
            
            # Send probe
            s.sendall(try_probe())
            
            banner = s.recv(1024)

        s.close()
        
        decoded_banner = banner.decode(errors='ignore').strip()
        
        if is_ssl_response(banner) or not decoded_banner:
            return grab_https_banner(ip_address, port)
        
        return decoded_banner
        
    except Exception as e:
        if port in [443, 8443, 80, 8080, 8000]:
            return grab_https_banner(ip_address, port)
        return f"Connection failed or error: {e}"


def is_ssl_response(data):
    ssl_signatures = [
        b'\x15\x03',  # TLS Alert
        b'\x16\x03',  # TLS Handshake
    ]
    return any(data.startswith(sig) for sig in ssl_signatures)


def grab_https_banner(ip_address, port):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        ssl_sock = context.wrap_socket(s, server_hostname=ip_address)
        ssl_sock.connect((ip_address, port))
        
        # Get certificate info
        cert_info = ""
        try:
            cert = ssl_sock.getpeercert()
            if cert and 'subject' in cert:
                for item in cert['subject']:
                    if item[0][0] == 'commonName':
                        cert_info = f"[SSL: {item[0][1]}] "
                        break
        except:
            pass
        
        ssl_sock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip_address.encode() + b"\r\n\r\n")
        banner = ssl_sock.recv(1024)
        ssl_sock.close()
        
        decoded = banner.decode(errors='ignore').strip()
        return cert_info + decoded if decoded else cert_info
        
    except Exception as e:
        return f"HTTPS error: {e}"


def grab_banners(ip, ports):
    results = {}
    for port in ports:
        banner = grab_banner(ip, port)
        if banner and not banner.startswith("Connection failed") and not banner.startswith("HTTPS error"):
            results[port] = banner
    return results
