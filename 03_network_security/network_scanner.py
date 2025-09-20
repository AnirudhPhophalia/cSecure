import socket
import threading
import time
import subprocess
import sys
from datetime import datetime

class PortScanner:
    def __init__(self):
        self.open_ports = []
        self.closed_ports = []
        self.scan_start_time = 0
        
    def scan_port(self, host, port, timeout=1):
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Attempt connection
            result = sock.connect_ex((host, port))
            sock.close()
            
            return result == 0
        except socket.gaierror:
            return False
        except Exception:
            return False
    
    def threaded_scan(self, host, port, timeout=1):
        if self.scan_port(host, port, timeout):
            self.open_ports.append(port)
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "unknown"
            print(f"Port {port}: OPEN ({service})")
        else:
            self.closed_ports.append(port)
    
    def scan_range(self, host, start_port, end_port, max_threads=100):
        print(f"=== PORT SCAN RESULTS FOR {host} ===")
        print(f"Scanning ports {start_port}-{end_port}")
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 50)
        
        self.scan_start_time = time.time()
        self.open_ports = []
        self.closed_ports = []
        
        threads = []
        
        for port in range(start_port, end_port + 1):
            # Limit concurrent threads
            while len(threads) >= max_threads:
                threads = [t for t in threads if t.is_alive()]
                time.sleep(0.01)
            
            thread = threading.Thread(target=self.threaded_scan, args=(host, port))
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        scan_time = time.time() - self.scan_start_time
        
        print("-" * 50)
        print(f"Scan completed in {scan_time:.2f} seconds")
        print(f"Open ports: {len(self.open_ports)}")
        print(f"Closed ports: {len(self.closed_ports)}")
        
        if self.open_ports:
            print(f"Open ports: {', '.join(map(str, sorted(self.open_ports)))}")
    
    def scan_common_ports(self, host):
        """Scan commonly used ports"""
        common_ports = [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            53,    # DNS
            80,    # HTTP
            110,   # POP3
            143,   # IMAP
            443,   # HTTPS
            993,   # IMAPS
            995,   # POP3S
            1433,  # SQL Server
            3306,  # MySQL
            3389,  # RDP
            5432,  # PostgreSQL
            6379,  # Redis
            8080,  # HTTP Alternative
            8443   # HTTPS Alternative
        ]
        
        print(f"=== COMMON PORTS SCAN FOR {host} ===")
        print("Scanning well-known service ports...")
        print("-" * 50)
        
        open_services = []
        
        for port in common_ports:
            if self.scan_port(host, port, 2):
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "unknown"
                
                print(f"Port {port}: OPEN ({service})")
                open_services.append((port, service))
            else:
                print(f"Port {port}: CLOSED")
        
        print("-" * 50)
        print(f"Found {len(open_services)} open services")
        return open_services

class NetworkRecon:
    def __init__(self):
        pass
    
    def get_local_ip(self):
        """Get local machine IP address"""
        try:
            # Connect to a remote address to determine local IP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
            sock.close()
            return local_ip
        except Exception:
            return "127.0.0.1"
    
    def resolve_hostname(self, hostname):
        """Resolve hostname to IP address"""
        try:
            ip = socket.gethostbyname(hostname)
            return ip
        except socket.gaierror as e:
            return f"Error: {e}"
    
    def reverse_dns_lookup(self, ip):
        """Perform reverse DNS lookup"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except socket.herror:
            return "No reverse DNS record found"
    
    def get_network_info(self, host):
        print(f"=== NETWORK RECONNAISSANCE FOR {host} ===")
        
        # Resolve hostname if needed
        if not self._is_ip_address(host):
            print(f"Hostname: {host}")
            ip = self.resolve_hostname(host)
            print(f"IP Address: {ip}")
        else:
            ip = host
            hostname = self.reverse_dns_lookup(ip)
            print(f"IP Address: {ip}")
            print(f"Hostname: {hostname}")
        
        # Check if host is reachable
        is_alive = self.ping_host(ip)
        print(f"Host Status: {'ALIVE' if is_alive else 'DOWN/FILTERED'}")
        
        # Get local network info
        local_ip = self.get_local_ip()
        print(f"Your IP: {local_ip}")
        
        return ip if self._is_ip_address(ip) else None
    
    def _is_ip_address(self, address):
        """Check if string is a valid IP address"""
        try:
            socket.inet_aton(address)
            return True
        except socket.error:
            return False
    
    def ping_host(self, host, count=1):
        """Simple ping implementation"""
        try:
            # Use system ping command
            if sys.platform.startswith('win'):
                result = subprocess.run(['ping', '-n', str(count), host], 
                                      capture_output=True, text=True, timeout=5)
            else:
                result = subprocess.run(['ping', '-c', str(count), host], 
                                      capture_output=True, text=True, timeout=5)
            
            return result.returncode == 0
        except Exception:
            return False

class ServiceDetector:
    def __init__(self):
        self.banner_timeouts = 3
    
    def grab_banner(self, host, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.banner_timeouts)
            sock.connect((host, port))
            
            # Send a generic request to trigger banner
            if port in [80, 8080]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
            elif port in [21, 22, 23, 25]:
                pass  # These usually send banner immediately
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else "No banner received"
            
        except Exception as e:
            return f"Error: {e}"
    
    def detect_service(self, host, port):
        print(f"=== SERVICE DETECTION FOR {host}:{port} ===")
        
        # Check if port is open
        scanner = PortScanner()
        if not scanner.scan_port(host, port, 3):
            return {"status": "closed", "service": None, "banner": None}
        
        # Try to get service name
        try:
            service_name = socket.getservbyport(port)
        except OSError:
            service_name = "unknown"
        
        # Grab banner
        banner = self.grab_banner(host, port)
        
        print(f"Port: {port}")
        print(f"Status: OPEN")
        print(f"Service: {service_name}")
        print(f"Banner: {banner}")
        
        return {
            "status": "open",
            "service": service_name,
            "banner": banner
        }

def demonstrate_network_scanning():
    print("=== NETWORK SECURITY SCANNING DEMONSTRATION ===\n")
    
    recon = NetworkRecon()
    scanner = PortScanner()
    detector = ServiceDetector()
    
    # Show local network info
    print("1. LOCAL NETWORK INFORMATION")
    local_ip = recon.get_local_ip()
    print(f"Your local IP: {local_ip}")
    print()
    
    # Example target (using localhost for safety)
    target = "127.0.0.1"  # localhost
    print(f"2. RECONNAISSANCE OF {target}")
    recon.get_network_info(target)
    print()
    
    # Common ports scan
    print("3. COMMON PORTS SCAN")
    open_services = scanner.scan_common_ports(target)
    print()
    
    # Service detection on open ports
    if open_services:
        print("4. SERVICE DETECTION")
        for port, service in open_services[:3]:  # Limit to first 3 for demo
            detector.detect_service(target, port)
            print()
    
    # Quick port range scan
    print("5. QUICK PORT RANGE SCAN")
    print("Scanning a small range for demonstration...")
    scanner.scan_range(target, 79, 82, max_threads=10)

def main():
    print("=== NETWORK SECURITY LEARNING TOOL ===\n")
    
    recon = NetworkRecon()
    scanner = PortScanner()
    detector = ServiceDetector()
    
    while True:
        print("\nChoose an option:")
        print("1. Scan common ports")
        print("2. Scan port range")
        print("3. Service detection")
        print("4. Network reconnaissance")
        print("5. Run full demonstration")
        print("6. Exit")
        
        choice = input("Your choice (1-6): ")
        
        if choice == '1':
            target = input("Enter target (IP or hostname): ")
            if target:
                scanner.scan_common_ports(target)
        
        elif choice == '2':
            target = input("Enter target (IP or hostname): ")
            start = input("Start port (default 1): ")
            end = input("End port (default 1000): ")
            
            try:
                start_port = int(start) if start else 1
                end_port = int(end) if end else 1000
                
                if end_port - start_port > 5000:
                    print("Warning: Large port range may take a long time!")
                    confirm = input("Continue? (y/n): ")
                    if confirm.lower() != 'y':
                        continue
                
                scanner.scan_range(target, start_port, end_port)
                
            except ValueError:
                print("Invalid port numbers!")
        
        elif choice == '3':
            target = input("Enter target (IP or hostname): ")
            port = input("Enter port number: ")
            
            try:
                port_num = int(port)
                detector.detect_service(target, port_num)
            except ValueError:
                print("Invalid port number!")
        
        elif choice == '4':
            target = input("Enter target (IP or hostname): ")
            if target:
                recon.get_network_info(target)
        
        elif choice == '5':
            print("Running full demonstration on localhost...")
            demonstrate_network_scanning()
        
        elif choice == '6':
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice!")

if __name__ == "__main__":
    main()