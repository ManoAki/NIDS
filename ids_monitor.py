import scapy.all as scapy
from collections import defaultdict, deque
import time
import hashlib
import os
import logging
import signal
from datetime import datetime
import subprocess
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from web_app import db, SecurityEvent

# Configure logging
logging.basicConfig(
    filename='ids.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class IDSMonitor:
    def __init__(self):
        self.connection_count = defaultdict(int)
        self.port_scan_count = defaultdict(lambda: defaultdict(int))
        self.syn_count = defaultdict(int)
        self.last_reset = time.time()
        self.secure_file = "secure_file.txt"
        self.file_hash = self.calculate_file_hash()
        self.running = True
        signal.signal(signal.SIGINT, self.signal_handler)
        self.time_window = 30  # Reduced to 30 seconds for better accuracy
        self.packet_history = defaultdict(lambda: deque(maxlen=1000))
        self.seq_numbers = defaultdict(set)
        self.udp_count = defaultdict(int)
        self.last_packet_time = defaultdict(float)
        self.port_scan_patterns = defaultdict(lambda: {
            'syn_scan': 0,
            'null_scan': 0,
            'fin_scan': 0,
            'xmas_scan': 0,
            'ack_scan': 0,
            'window_scan': 0,
            'last_scan_time': 0,
            'timing_match': False
        })
        self.scan_timing = defaultdict(list)  # Track timing between packets
        self.port_sequence = defaultdict(list)  # Track port scanning sequence
        self.packet_sizes = defaultdict(list)  # Track packet sizes
        self.blocked_ips = set()  # Track blocked IPs
        self.attack_counts = defaultdict(lambda: {'nmap': 0, 'dos': 0})  # Track attack counts
        self.allowed_ips_file = "allowed_ips.txt"
        self.blocked_ips_file = "blocked_ips.txt"
        self.allowed_ips = self.load_ip_list(self.allowed_ips_file)
        self.blocked_ips = self.load_ip_list(self.blocked_ips_file)
        # Add these lines for immediate blocking
        self.setup_iptables()
        # Email configuration
        self.email_config = {
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'sender_email': 'srivenkatesh0555@gmail.com',  # Replace with your Gmail
            'sender_password': 'gvskafsdtiutjtxb ',  # Replace with Gmail app password
            'recipient_email': 'srivenkatesh0555@gmail.com'  # Replace with recipient email
        }
        # Initialize Flask app context
        from web_app import app
        self.app = app
        self.app_context = app.app_context()
        self.app_context.push()
        
    def load_ip_list(self, filename):
        """Load IP addresses from file"""
        ip_set = set()
        try:
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        ip_set.add(line)
        except FileNotFoundError:
            with open(filename, 'w') as f:
                f.write("# One IP address per line\n")
        return ip_set

    def save_blocked_ips(self):
        """Save blocked IPs to file"""
        with open(self.blocked_ips_file, 'w') as f:
            f.write("# One IP address per line\n")
            for ip in self.blocked_ips:
                f.write(f"{ip}\n")

    def calculate_file_hash(self):
        if not os.path.exists(self.secure_file):
            with open(self.secure_file, 'w') as f:
                f.write("This is a secure file. Do not modify.")
        with open(self.secure_file, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    
    def check_file_integrity(self):
        current_hash = self.calculate_file_hash()
        if current_hash != self.file_hash:
            timestamp = datetime.now()
            alert = f"WARNING: secure_file.txt has been modified at {timestamp}"
            logging.warning(alert)
            print(alert)
            
            # Create security event with hash information
            self.log_security_event(
                event_type="File Modification",
                source_ip="local",
                details=f"File: secure_file.txt was modified",
                severity="HIGH",
                old_hash=self.file_hash,
                new_hash=current_hash
            )
            
            self.file_hash = current_hash
    
    def analyze_packet_pattern(self, src_ip, packet_time, packet_size, packet=None):
        history = self.packet_history[src_ip]
        dst_port = packet[scapy.TCP].dport if packet and packet.haslayer(scapy.TCP) else None
        history.append((packet_time, dst_port if dst_port else packet_size))
        
        # Clean old entries
        current_time = time.time()
        while history and history[0][0] < current_time - self.time_window:
            history.popleft()
            
        if len(history) >= 2:
            time_diff = history[-1][0] - history[0][0]
            packet_rate = len(history) / time_diff if time_diff > 0 else float('inf')
            return packet_rate
        return 0

    def detect_nmap_scan(self, packet, src_ip):
        if not packet.haslayer(scapy.TCP):
            return False
            
        tcp = packet[scapy.TCP]
        current_time = time.time()
        
        try:
            # Track ports accessed
            current_port = int(tcp.dport)
            self.port_sequence[src_ip].append((current_time, current_port))
            
            # Clean old entries but keep more history for pattern detection
            while (self.port_sequence[src_ip] and 
                   current_time - self.port_sequence[src_ip][0][0] > self.time_window * 2):
                self.port_sequence[src_ip].pop(0)
            
            # Get recent port activity with expanded window
            recent_ports = [p[1] for p in self.port_sequence[src_ip][-100:]]  # Increased sample size
            unique_ports = len(set(recent_ports))
            
            # Enhanced Nmap detection
            if len(recent_ports) >= 3:  # Reduced minimum samples for faster detection
                sorted_ports = sorted(set(recent_ports))
                
                # Detect common Nmap patterns
                sequential_count = sum(1 for i in range(len(sorted_ports)-1) 
                                    if sorted_ports[i+1] - sorted_ports[i] in (1, 2, 5, 10))  # Common Nmap increments
                
                port_range = sorted_ports[-1] - sorted_ports[0] if sorted_ports else 0
                
                # Check timing patterns
                timing_diffs = [self.port_sequence[src_ip][i+1][0] - self.port_sequence[src_ip][i][0] 
                              for i in range(len(self.port_sequence[src_ip])-1)]
                
                if timing_diffs:
                    avg_timing = sum(timing_diffs) / len(timing_diffs)
                    timing_pattern = all(0.01 <= t <= 2 for t in timing_diffs[-3:])  # Check last 3 timing intervals
                else:
                    avg_timing = 0
                    timing_pattern = False

                # Enhanced detection indicators
                indicators = {
                    'timing_match': timing_pattern,
                    'sequential_ports': sequential_count >= 2,
                    'common_ports': any(p in sorted_ports for p in [21, 22, 23, 25, 80, 443, 3306, 3389]),
                    'many_unique_ports': unique_ports >= 3,
                    'typical_range': 20 <= port_range <= 1000,
                    'consistent_timing': 0.01 <= avg_timing <= 2,
                    'syn_flags': bool(tcp.flags & 0x02),
                    'low_rate': len(recent_ports) / self.time_window < 50
                }
                
                # Weight-based scoring
                weights = {
                    'timing_match': 2,
                    'sequential_ports': 2,
                    'common_ports': 1,
                    'many_unique_ports': 1.5,
                    'typical_range': 1,
                    'consistent_timing': 2,
                    'syn_flags': 1.5,
                    'low_rate': 1
                }
                
                score = sum(weights[k] for k, v in indicators.items() if v)
                
                # Lower threshold for faster detection
                if score >= 6:  # Adjusted threshold
                    # Log detection details
                    logging.info(f"Nmap scan detected from {src_ip}. Score: {score}")
                    logging.info(f"Detection indicators: {indicators}")
                    return True
            
            return False

        except Exception as e:
            logging.error(f"Error in Nmap detection: {e}")
            return False

    def detect_dos_attack(self, packet, src_ip, packet_rate):
        if not packet.haslayer(scapy.TCP):
            return False
            
        try:
            tcp = packet[scapy.TCP]
            flags = int(tcp.flags)
            
            # Get recent port activity
            recent_ports = [p[1] for p in self.port_sequence[src_ip] if isinstance(p[1], int)]
            unique_ports = len(set(recent_ports))
            
            # DoS specific indicators
            is_syn_flood = bool(flags & 0x02)  # SYN flag set
            is_high_rate = packet_rate > 50  # High packet rate
            is_single_port = unique_ports <= 2  # Targeting few ports
            has_many_packets = len(self.packet_history[src_ip]) > 50  # Sustained attack
            not_scanning = len(self.port_sequence[src_ip]) < 20  # Not port scanning
            
            return all([
                is_syn_flood,
                is_high_rate,
                is_single_port,
                has_many_packets,
                not_scanning
            ])
            
        except Exception as e:
            logging.debug(f"Error in DoS detection: {e}")
            return False

    def setup_iptables(self):
        """Setup initial iptables rules"""
        try:
            # Flush existing rules and recreate chain
            subprocess.run("sudo iptables -F IDS_BLOCKS 2>/dev/null || sudo iptables -N IDS_BLOCKS", shell=True)
            # Ensure chain is linked to INPUT at the beginning
            subprocess.run("sudo iptables -D INPUT -j IDS_BLOCKS 2>/dev/null || true", shell=True)
            subprocess.run("sudo iptables -I INPUT 1 -j IDS_BLOCKS", shell=True)
            
            # Apply existing blocks from file
            for ip in self.blocked_ips:
                subprocess.run(f"sudo iptables -A IDS_BLOCKS -s {ip} -j DROP", shell=True)
                
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to setup iptables: {e}")

    def block_ip(self, ip_address, attack_type):
        """Block an IP using iptables and save to file"""
        if ip_address not in self.blocked_ips and ip_address not in self.allowed_ips:
            try:
                # Add more verbose logging
                logging.info(f"Attempting to block IP {ip_address}")
                
                # More robust command execution with output capture
                cmd = f"sudo iptables -A IDS_BLOCKS -s {ip_address} -j DROP"
                result = subprocess.run(cmd.split(), capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.blocked_ips.add(ip_address)
                    self.save_blocked_ips()
                    alert = f"BLOCKED {ip_address} - {attack_type} attack detected"
                    logging.warning(alert)
                    print(alert)
                    
                    # Verify the block
                    verify_result = subprocess.run(f"sudo iptables -C IDS_BLOCKS -s {ip_address} -j DROP".split(), 
                                                  capture_output=True, text=True)
                    if verify_result.returncode == 0:
                        logging.info(f"Successfully verified block for {ip_address}")
                    else:
                        logging.error(f"Block verification failed for {ip_address}: {verify_result.stderr}")
                else:
                    logging.error(f"Failed to block {ip_address}: {result.stderr}")
                    
            except Exception as e:
                logging.error(f"Exception while blocking IP {ip_address}: {e}")

    def check_and_block(self, ip_address, attack_type):
        """Check attack counts and block if necessary"""
        self.attack_counts[ip_address][attack_type] += 1
        if self.attack_counts[ip_address][attack_type] >= 5:
            self.block_ip(ip_address, attack_type)

    def send_email_alert(self, subject, message):
        """Send email alert for security incidents"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_config['sender_email']
            msg['To'] = self.email_config['recipient_email']
            msg['Subject'] = f"IDS Alert: {subject}"
            
            msg.attach(MIMEText(message, 'plain'))
            
            with smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port']) as server:
                server.starttls()
                server.login(self.email_config['sender_email'], self.email_config['sender_password'])
                server.send_message(msg)
                
            logging.info(f"Alert email sent: {subject}")
        except Exception as e:
            logging.error(f"Failed to send email alert: {str(e)}")

    def log_security_event(self, event_type, source_ip, details, severity, old_hash=None, new_hash=None):
        """Log security event to database and broadcast to web clients"""
        timestamp = datetime.now()
        
        # Create base event data
        event_data = {
            'timestamp': timestamp,
            'event_type': event_type,
            'details': details,
            'severity': severity
        }

        if event_type == "File Modification":
            # For file modifications, include hash info
            event = SecurityEvent(
                timestamp=timestamp,
                event_type=event_type,
                details=details,
                severity=severity,
                old_hash=old_hash,
                new_hash=new_hash
            )
        else:
            # For other events, include network info
            dest_ip = getattr(self.current_packet[scapy.IP], 'dst', 'Unknown')
            dest_port = None
            protocol = 'UDP' if self.current_packet.haslayer(scapy.UDP) else 'TCP'
            
            if self.current_packet.haslayer(scapy.TCP):
                dest_port = self.current_packet[scapy.TCP].dport
            elif self.current_packet.haslayer(scapy.UDP):
                dest_port = self.current_packet[scapy.UDP].dport
                
            event = SecurityEvent(
                timestamp=timestamp,
                event_type=event_type,
                source_ip=source_ip,
                dest_ip=dest_ip,
                dest_port=dest_port,
                protocol=protocol,
                details=details,
                severity=severity
            )
            
        db.session.add(event)
        db.session.commit()
        
        # Broadcast event
        from web_app import broadcast_event
        broadcast_event({
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'event_type': event_type,
            'details': details,
            'severity': severity,
            'alert_id': f"alert_{int(time.time())}"
        })

    def packet_callback(self, packet):
        if packet.haslayer(scapy.IP):
            # Store packet for reference
            self.current_packet = packet
            src_ip = packet[scapy.IP].src
            current_time = time.time()
            
            # Quick check for already blocked IPs
            if src_ip in self.blocked_ips:
                return
                    
            if src_ip in self.allowed_ips:
                return
            
            try:
                # Immediate port scan check
                if packet.haslayer(scapy.TCP):
                    if self.detect_nmap_scan(packet, src_ip):
                        scan_type = self.determine_scan_type(packet)
                        alert = f"NMAP SCAN DETECTED - Type: {scan_type} from {src_ip}"
                        # Block immediately without waiting
                        self.block_ip(src_ip, f"Nmap {scan_type}")
                        self.log_security_event("NMAP Scan", src_ip, alert, "HIGH")
                        self.send_email_alert("Nmap Scan Detected", alert)
                        return  # Stop processing this packet
                        
                packet_rate = self.analyze_packet_pattern(src_ip, current_time, len(packet), packet)
                
                if packet.haslayer(scapy.TCP):
                    # Immediate blocking for detected attacks
                    if self.detect_dos_attack(packet, src_ip, packet_rate):
                        alert = f"DoS ATTACK DETECTED - SYN Flood from {src_ip}"
                        self.log_security_event("DoS Attack", src_ip, alert, "HIGH")
                        logging.warning(alert)
                        print(alert)
                        self.send_email_alert("DoS Attack Detected", alert)
                        self.block_ip(src_ip, "DoS attack")
                
                # UDP flood detection with immediate blocking
                elif packet.haslayer(scapy.UDP):
                    if packet_rate > 150:
                        alert = f"UDP FLOOD ATTACK from {src_ip}"
                        self.log_security_event("UDP Flood", src_ip, alert, "HIGH")
                        logging.warning(alert)
                        print(alert)
                        self.send_email_alert("UDP Flood Attack", alert)
                        self.block_ip(src_ip, "UDP flood")
                        
            except Exception as e:
                logging.error(f"Error processing packet: {e}")

            # Clean up old data
            if current_time - self.last_reset > 3600:
                self.connection_count.clear()
                self.port_scan_count.clear()
                self.syn_count.clear()
                self.last_reset = time.time()
                self.seq_numbers.clear()
                self.udp_count.clear()
                self.packet_history.clear()
                self.port_scan_patterns.clear()
                self.scan_timing.clear()
                self.port_sequence.clear()
                self.packet_sizes.clear()
                self.attack_counts.clear()  # Reset attack counts hourly
    
    def determine_scan_type(self, packet):
        tcp = packet[scapy.TCP]
        flags = int(tcp.flags)
        
        if flags & 0x02:
            return "SYN scan"
        elif flags & 0x01:
            return "FIN scan"
        elif flags == 0:
            return "NULL scan"
        elif flags & 0x29:
            return "XMAS scan"
        return "Unknown scan"

    def signal_handler(self, signum, frame):
        print("\nShutting down IDS monitor...")
        # Clean up iptables rules
        try:
            subprocess.run("sudo iptables -F IDS_BLOCKS", shell=True)
            subprocess.run("sudo iptables -D INPUT -j IDS_BLOCKS 2>/dev/null || true", shell=True)
        except subprocess.CalledProcessError:
            pass
        self.running = False
        logging.info("IDS monitor shutdown initiated by user")
    
    def start_monitoring(self):
        print("Starting IDS monitoring... (Press Ctrl+C to exit)")
        print(f"Loaded {len(self.allowed_ips)} allowed IPs and {len(self.blocked_ips)} blocked IPs")
        # Verify all blocks are in place
        self.setup_iptables()
        while self.running:
            try:
                scapy.sniff(prn=self.packet_callback, store=0, timeout=10)
                self.check_file_integrity()
            except Exception as e:
                if self.running:  # Only log errors if not shutting down
                    logging.error(f"Error in monitoring: {str(e)}")
                    print(f"Error: {str(e)}")
        print("IDS monitor stopped.")

if __name__ == "__main__":
    ids = IDSMonitor()
    ids.start_monitoring()
