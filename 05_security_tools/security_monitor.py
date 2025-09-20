import os
import hashlib
import time
import json
import psutil
import threading
from datetime import datetime
from pathlib import Path

class FileIntegrityMonitor:
    """Monitor file changes and detect unauthorized modifications"""
    
    def __init__(self, monitor_paths=None):
        self.monitor_paths = monitor_paths or []
        self.baseline = {}
        self.baseline_file = "file_integrity_baseline.json"
        self.suspicious_extensions = ['.exe', '.bat', '.cmd', '.scr', '.vbs', '.ps1']
    
    def calculate_file_hash(self, filepath):
        """Calculate SHA-256 hash of a file"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            return f"Error: {e}"
    
    def get_file_info(self, filepath):
        """Get comprehensive file information"""
        try:
            stat = os.stat(filepath)
            return {
                'size': stat.st_size,
                'modified': stat.st_mtime,
                'created': stat.st_ctime,
                'hash': self.calculate_file_hash(filepath),
                'permissions': oct(stat.st_mode)[-3:]
            }
        except Exception as e:
            return {'error': str(e)}
    
    def create_baseline(self):
        """Create baseline of all monitored files"""
        print("=== CREATING FILE INTEGRITY BASELINE ===")
        self.baseline = {}
        
        for monitor_path in self.monitor_paths:
            if os.path.isfile(monitor_path):
                self.baseline[monitor_path] = self.get_file_info(monitor_path)
                print(f"Added file: {monitor_path}")
            elif os.path.isdir(monitor_path):
                for root, dirs, files in os.walk(monitor_path):
                    for file in files:
                        filepath = os.path.join(root, file)
                        self.baseline[filepath] = self.get_file_info(filepath)
                        print(f"Added file: {filepath}")
        
        # Save baseline to file
        try:
            with open(self.baseline_file, 'w') as f:
                json.dump(self.baseline, f, indent=2)
            print(f"Baseline saved to {self.baseline_file}")
            print(f"Total files monitored: {len(self.baseline)}")
        except Exception as e:
            print(f"Error saving baseline: {e}")
    
    def load_baseline(self):
        """Load baseline from file"""
        try:
            with open(self.baseline_file, 'r') as f:
                self.baseline = json.load(f)
            print(f"Baseline loaded: {len(self.baseline)} files")
            return True
        except FileNotFoundError:
            print("No baseline file found. Please create baseline first.")
            return False
        except Exception as e:
            print(f"Error loading baseline: {e}")
            return False
    
    def check_integrity(self):
        """Check current state against baseline"""
        print("=== FILE INTEGRITY CHECK ===")
        
        if not self.baseline:
            if not self.load_baseline():
                return
        
        changes_detected = []
        new_files = []
        deleted_files = []
        
        # Check existing files for changes
        current_files = set()
        
        for monitor_path in self.monitor_paths:
            if os.path.isfile(monitor_path):
                current_files.add(monitor_path)
                if monitor_path in self.baseline:
                    current_info = self.get_file_info(monitor_path)
                    baseline_info = self.baseline[monitor_path]
                    
                    if current_info.get('hash') != baseline_info.get('hash'):
                        changes_detected.append({
                            'file': monitor_path,
                            'type': 'modified',
                            'baseline_hash': baseline_info.get('hash'),
                            'current_hash': current_info.get('hash')
                        })
                else:
                    new_files.append(monitor_path)
                    
            elif os.path.isdir(monitor_path):
                for root, dirs, files in os.walk(monitor_path):
                    for file in files:
                        filepath = os.path.join(root, file)
                        current_files.add(filepath)
                        
                        if filepath in self.baseline:
                            current_info = self.get_file_info(filepath)
                            baseline_info = self.baseline[filepath]
                            
                            if current_info.get('hash') != baseline_info.get('hash'):
                                changes_detected.append({
                                    'file': filepath,
                                    'type': 'modified',
                                    'baseline_hash': baseline_info.get('hash'),
                                    'current_hash': current_info.get('hash')
                                })
                        else:
                            new_files.append(filepath)
        
        # Check for deleted files
        baseline_files = set(self.baseline.keys())
        deleted_files = list(baseline_files - current_files)
        
        # Report results
        print(f"Files checked: {len(current_files)}")
        print(f"Changes detected: {len(changes_detected)}")
        print(f"New files: {len(new_files)}")
        print(f"Deleted files: {len(deleted_files)}")
        
        if changes_detected:
            print("\n--- MODIFIED FILES ---")
            for change in changes_detected:
                print(f"MODIFIED: {change['file']}")
                print(f"  Old hash: {change['baseline_hash']}")
                print(f"  New hash: {change['current_hash']}")
        
        if new_files:
            print("\n--- NEW FILES ---")
            for file in new_files[:10]:  # Limit output
                print(f"NEW: {file}")
                if Path(file).suffix.lower() in self.suspicious_extensions:
                    print(f" SUSPICIOUS: Executable file type")
        
        if deleted_files:
            print("\n--- DELETED FILES ---")
            for file in deleted_files[:10]:  # Limit output
                print(f"DELETED: {file}")
        
        return {
            'modified': changes_detected,
            'new': new_files,
            'deleted': deleted_files
        }

class BasicMalwareDetector:
    """Basic malware detection using signatures and heuristics"""
    
    def __init__(self):
        # Simple malware signatures (for educational purposes)
        self.signatures = {
            'test_malware': b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
            'suspicious_pattern1': b'eval(base64_decode(',
            'suspicious_pattern2': b'cmd.exe /c',
            'suspicious_pattern3': b'powershell.exe -enc',
        }
        
        self.suspicious_strings = [
            'CreateObject("WScript.Shell")',
            'System32\\cmd.exe',
            'powershell.exe',
            'reg add HKLM',
            'net user',
            'schtasks /create',
        ]
        
        self.risk_score_threshold = 50
    
    def scan_file(self, filepath):
        """Scan a single file for malware signatures"""
        try:
            with open(filepath, 'rb') as f:
                content = f.read()
            
            detections = []
            risk_score = 0
            
            # Check binary signatures
            for sig_name, signature in self.signatures.items():
                if signature in content:
                    detections.append(f"Binary signature: {sig_name}")
                    risk_score += 75
            
            # Check suspicious strings
            content_str = content.decode('utf-8', errors='ignore')
            for suspicious in self.suspicious_strings:
                if suspicious.lower() in content_str.lower():
                    detections.append(f"Suspicious string: {suspicious}")
                    risk_score += 25
            
            # Heuristic checks
            if filepath.endswith('.exe') and os.path.getsize(filepath) < 10000:
                detections.append("Heuristic: Small executable file")
                risk_score += 20
            
            if filepath.endswith(('.bat', '.cmd', '.vbs', '.ps1')):
                detections.append("Heuristic: Script file type")
                risk_score += 15
            
            # Check for obfuscation
            if len([c for c in content_str if not c.isprintable()]) > len(content_str) * 0.3:
                detections.append("Heuristic: High non-printable character ratio")
                risk_score += 30
            
            return {
                'filepath': filepath,
                'detections': detections,
                'risk_score': risk_score,
                'threat_level': self._get_threat_level(risk_score)
            }
            
        except Exception as e:
            return {
                'filepath': filepath,
                'error': str(e),
                'risk_score': 0,
                'threat_level': 'ERROR'
            }
    
    def _get_threat_level(self, risk_score):
        """Determine threat level based on risk score"""
        if risk_score >= 75:
            return 'HIGH'
        elif risk_score >= 50:
            return 'MEDIUM'
        elif risk_score >= 25:
            return 'LOW'
        else:
            return 'CLEAN'
    
    def scan_directory(self, directory_path):
        """Scan all files in a directory"""
        print(f"=== MALWARE SCAN: {directory_path} ===")
        
        scan_results = []
        file_count = 0
        
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                filepath = os.path.join(root, file)
                result = self.scan_file(filepath)
                scan_results.append(result)
                file_count += 1
                
                # Print immediate results for high-risk files
                if result.get('threat_level') in ['HIGH', 'MEDIUM']:
                    print(f"\n THREAT DETECTED: {filepath}")
                    print(f"   Threat Level: {result['threat_level']}")
                    print(f"   Risk Score: {result['risk_score']}")
                    for detection in result.get('detections', []):
                        print(f"   - {detection}")
        
        # Summary
        threat_counts = {}
        for result in scan_results:
            level = result.get('threat_level', 'ERROR')
            threat_counts[level] = threat_counts.get(level, 0) + 1
        
        print(f"\n--- SCAN SUMMARY ---")
        print(f"Files scanned: {file_count}")
        for level, count in threat_counts.items():
            print(f"{level}: {count}")
        
        return scan_results

class SystemMonitor:
    """Monitor system for suspicious activities"""
    
    def __init__(self):
        self.monitoring = False
        self.log_file = "security_monitor.log"
        self.suspicious_processes = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe']
        self.baseline_network_connections = set()
    
    def log_event(self, event_type, message):
        """Log security events to file"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {event_type}: {message}\n"
        
        try:
            with open(self.log_file, 'a') as f:
                f.write(log_entry)
        except Exception as e:
            print(f"Logging error: {e}")
        
        print(log_entry.strip())
    
    def monitor_processes(self):
        """Monitor for suspicious process activities"""
        print("Monitoring processes...")
        known_processes = set()
        
        while self.monitoring:
            try:
                current_processes = set()
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        proc_info = proc.info
                        proc_id = f"{proc_info['pid']}:{proc_info['name']}"
                        current_processes.add(proc_id)
                        
                        # Check for new suspicious processes
                        if proc_id not in known_processes:
                            if proc_info['name'] in self.suspicious_processes:
                                cmdline = ' '.join(proc_info['cmdline'] or [])
                                self.log_event('SUSPICIOUS_PROCESS', 
                                             f"New process: {proc_info['name']} (PID: {proc_info['pid']}) - {cmdline}")
                    except Exception as e:
                        self.log_event('ERROR', f"Error accessing process info: {e}")
                
                known_processes.update(current_processes)
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                self.log_event('ERROR', f"Process monitoring error: {e}")
                time.sleep(5)
    
    def monitor_network(self):
        """Monitor network connections for anomalies"""
        print("Monitoring network connections...")
        
        # Establish baseline
        if not self.baseline_network_connections:
            for conn in psutil.net_connections():
                if conn.status == 'ESTABLISHED':
                    self.baseline_network_connections.add(f"{conn.laddr.ip}:{conn.laddr.port}->{conn.raddr.ip}:{conn.raddr.port}")
        
        while self.monitoring:
            try:
                current_connections = set()
                for conn in psutil.net_connections():
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        conn_str = f"{conn.laddr.ip}:{conn.laddr.port}->{conn.raddr.ip}:{conn.raddr.port}"
                        current_connections.add(conn_str)
                        
                        # Check for new outbound connections
                        if conn_str not in self.baseline_network_connections:
                            if conn.laddr.ip != '127.0.0.1':  # Ignore localhost
                                self.log_event('NEW_CONNECTION', 
                                             f"New outbound connection: {conn_str}")
                
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                self.log_event('ERROR', f"Network monitoring error: {e}")
                time.sleep(10)
    
    def start_monitoring(self):
        """Start all monitoring threads"""
        print("=== STARTING SYSTEM MONITORING ===")
        self.monitoring = True
        
        # Start monitoring threads
        process_thread = threading.Thread(target=self.monitor_processes)
        network_thread = threading.Thread(target=self.monitor_network)
        
        process_thread.daemon = True
        network_thread.daemon = True
        
        process_thread.start()
        network_thread.start()
        
        print("Monitoring started. Press Ctrl+C to stop.")
        
        try:
            while self.monitoring:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping monitoring...")
            self.monitoring = False
    
    def get_system_info(self):
        """Get current system information"""
        print("=== SYSTEM INFORMATION ===")
        
        # CPU and Memory
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        print(f"CPU Usage: {cpu_percent}%")
        print(f"Memory Usage: {memory.percent}% ({memory.used // (1024**2)} MB / {memory.total // (1024**2)} MB)")
        
        # Disk usage
        disk = psutil.disk_usage('/')
        print(f"Disk Usage: {(disk.used / disk.total) * 100:.1f}% ({disk.used // (1024**3)} GB / {disk.total // (1024**3)} GB)")
        
        # Network interfaces
        print("\nNetwork Interfaces:")
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == 2:  # IPv4
                    print(f"  {interface}: {addr.address}")
        
        # Running processes count
        process_count = len(list(psutil.process_iter()))
        print(f"\nRunning Processes: {process_count}")
        
        # Network connections
        connections = len([c for c in psutil.net_connections() if c.status == 'ESTABLISHED'])
        print(f"Active Network Connections: {connections}")

def main():
    """Main function demonstrating all security utilities"""
    print("=== SECURITY UTILITIES ===")
    print("Tools for file integrity monitoring, malware detection, and system monitoring")
    
    # Initialize components
    monitor_paths = [os.getcwd()]  # Monitor current directory by default
    fim = FileIntegrityMonitor(monitor_paths)
    malware_detector = BasicMalwareDetector()
    system_monitor = SystemMonitor()
    
    while True:
        print("\nChoose a security tool:")
        print("1. File Integrity Monitoring")
        print("2. Malware Scanner")
        print("3. System Information")
        print("4. Start System Monitoring")
        print("5. Create test files for demonstration")
        print("6. Exit")
        
        choice = input("Your choice (1-6): ")
        
        if choice == '1':
            print("\nFile Integrity Monitor:")
            print("a. Create baseline")
            print("b. Check integrity")
            print("c. Load existing baseline")
            
            sub_choice = input("Your choice (a-c): ")
            if sub_choice == 'a':
                fim.create_baseline()
            elif sub_choice == 'b':
                fim.check_integrity()
            elif sub_choice == 'c':
                fim.load_baseline()
        
        elif choice == '2':
            scan_path = input("Enter path to scan (default: current directory): ")
            if not scan_path:
                scan_path = os.getcwd()
            
            if os.path.exists(scan_path):
                if os.path.isfile(scan_path):
                    result = malware_detector.scan_file(scan_path)
                    print(f"\nScan result for {scan_path}:")
                    print(f"Threat Level: {result.get('threat_level')}")
                    print(f"Risk Score: {result.get('risk_score')}")
                    for detection in result.get('detections', []):
                        print(f"- {detection}")
                else:
                    malware_detector.scan_directory(scan_path)
            else:
                print("Path does not exist!")
        
        elif choice == '3':
            system_monitor.get_system_info()
        
        elif choice == '4':
            print("Starting system monitoring (experimental feature)...")
            print("Note: This will monitor processes and network connections.")
            confirm = input("Continue? (y/n): ")
            if confirm.lower() == 'y':
                try:
                    system_monitor.start_monitoring()
                except Exception as e:
                    print(f"Monitoring error: {e}")
        
        elif choice == '5':
            print("Creating test files for demonstration...")
            
            # Create EICAR test file (harmless test virus)
            eicar_content = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
            with open('eicar_test.txt', 'wb') as f:
                f.write(eicar_content)
            
            # Create suspicious script
            suspicious_script = '''
            import os
            import subprocess
            # This is a test script - it doesn't actually do anything harmful
            # subprocess.call(['cmd.exe', '/c', 'echo', 'This is a test'])
            print("Test script executed")
            '''
            with open('suspicious_test.py', 'w') as f:
                f.write(suspicious_script)
            
            print("Test files created:")
            print("- eicar_test.txt (contains EICAR test signature)")
            print("- suspicious_test.py (contains suspicious patterns)")
            print("Use these for testing the malware scanner!")
        
        elif choice == '6':
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice!")

if __name__ == "__main__":
    try:
        main()
    except ImportError as e:
        print(f"Error: {e}")
        print("\nTo run this script, install the required library:")
        print("pip install psutil")