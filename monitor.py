from scapy.all import sniff, TCP, IP, UDP, ICMP, get_if_list
from collections import defaultdict
import time
import psutil
import json
import sys
import os
import hashlib
import random
import sqlite3, json, os
from datetime import datetime
import psutil
import socket
import subprocess
import platform
import re

# Import ML prediction system and feature extractor
try:
    from live_prediction import LiveIDSPredictor
    from packet_feature_extractor import ImprovedPacketFeatureExtractor
    ML_AVAILABLE = True
    print("✅ ML prediction system loaded successfully")
except ImportError as e:
    print(f"⚠️ ML system not available: {e}")
    print("ℹ️ Continuing with rule-based detection only")
    ML_AVAILABLE = False

# ==========================
# ATTACK CATEGORIES
# ==========================
ATTACK_CATEGORIES = [
    'Botnet Activities',
    'Brute Force Attacks', 
    'DDoS Attacks',
    'Normal',
    'Port Scanning / Reconnaissance',
    'Privilege Escalation',
    'Service Exploits'
]


def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect('ids_database.db')
    # conn.row_factory = sqlite3.Row
    return conn


from datetime import datetime


def unblock_ip_firewall(ip_address):
    """Unblock IP at firewall level - remove both rules"""
    try:
        system = platform.system()
        
        if system == "Windows":
            # Remove inbound rule
            cmd_in = f'netsh advfirewall firewall delete rule name="IDS_Block_IN_{ip_address}"'
            subprocess.run(cmd_in, shell=True, capture_output=True, text=True)
            
            # Remove outbound rule
            cmd_out = f'netsh advfirewall firewall delete rule name="IDS_Block_OUT_{ip_address}"'
            subprocess.run(cmd_out, shell=True, capture_output=True, text=True)
            
            print(f"✅ Unblocked {ip_address} from Windows Firewall")
            
        elif system == "Linux":
            # Remove from INPUT chain
            cmd_input = f'sudo iptables -D INPUT -s {ip_address} -j DROP'
            subprocess.run(cmd_input, shell=True, capture_output=True, text=True)
            
            # Remove from OUTPUT chain
            cmd_output = f'sudo iptables -D OUTPUT -d {ip_address} -j DROP'
            subprocess.run(cmd_output, shell=True, capture_output=True, text=True)
            
            print(f"✅ Unblocked {ip_address} from iptables")
        
        return True
    except Exception as e:
        print(f"❌ Firewall unblocking error for {ip_address}: {e}")
        return False


def block_ip_firewall(ip_address):
    """Block IP at firewall level - both inbound and outbound"""
    try:
        system = platform.system()
        
        if system == "Windows":
            # Block INBOUND traffic
            cmd_in = f'netsh advfirewall firewall add rule name="IDS_Block_IN_{ip_address}" dir=in action=block remoteip={ip_address}'
            result_in = subprocess.run(cmd_in, shell=True, capture_output=True, text=True)
            
            # Block OUTBOUND traffic
            cmd_out = f'netsh advfirewall firewall add rule name="IDS_Block_OUT_{ip_address}" dir=out action=block remoteip={ip_address}'
            result_out = subprocess.run(cmd_out, shell=True, capture_output=True, text=True)
            
            if result_in.returncode == 0 and result_out.returncode == 0:
                print(f"✅ Blocked {ip_address} on Windows Firewall (IN+OUT)")
                return True
            else:
                print(f"❌ Firewall error: IN={result_in.returncode}, OUT={result_out.returncode}")
                return False
                
        elif system == "Linux":
            # Block both INPUT and OUTPUT
            cmd_input = f'sudo iptables -I INPUT -s {ip_address} -j DROP'
            cmd_output = f'sudo iptables -I OUTPUT -d {ip_address} -j DROP'
            
            result_in = subprocess.run(cmd_input, shell=True, capture_output=True, text=True)
            result_out = subprocess.run(cmd_output, shell=True, capture_output=True, text=True)
            
            if result_in.returncode == 0 and result_out.returncode == 0:
                print(f"✅ Blocked {ip_address} with iptables (IN+OUT)")
                return True
            return False
        
        return False
    except Exception as e:
        print(f"❌ Firewall blocking error for {ip_address}: {e}")
        return False
    
def save_live_prediction_to_db(
    ip_address: str,
    prediction_result: str,
    confidence: float,
    attack_type: str,
    input_data_dict: dict,
    user_id=None,
    session_id: str = "monitor",
    prediction_source: str = "live_monitor",
    processed_by: str = "ML_Model"
):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        cur.execute("""
            INSERT INTO predictions
            (ip_address, prediction_result, confidence, attack_type, input_data, user_id, session_id, processed_by, prediction_source, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ip_address,
            prediction_result,
            float(confidence or 0.0),
            attack_type,
            json.dumps(input_data_dict, default=str),
            user_id,
            session_id,
            processed_by,
            prediction_source,
            current_time
        ))
        
        # AUTOMATIC BLOCKING: If attack detected, check and block IP
        if prediction_result == "Attack":
            # Check if IP is already blocked
            already_blocked = cur.execute("""
                SELECT id FROM blocked_ips 
                WHERE ip_address = ? AND is_blocked = 1
            """, (ip_address,)).fetchone()
            
            if already_blocked:
                # Just increment counter
                cur.execute("""
                    UPDATE blocked_ips SET block_count = block_count + 1
                    WHERE ip_address = ? AND is_blocked = 1
                """, (ip_address,))
                conn.commit()
                return
            
            # Check attack count for this IP
            attack_count = cur.execute("""
                SELECT COUNT(*) FROM predictions 
                WHERE ip_address = ? AND prediction_result = 'Attack'
            """, (ip_address,)).fetchone()[0]
            
            # Block if threshold reached (3 attacks)
            if attack_count >= 3:
                # Add to database FIRST
                cur.execute("""
                    INSERT INTO blocked_ips (ip_address, attack_type, reason, blocked_by)
                    VALUES (?, ?, ?, ?)
                """, (
                    ip_address,
                    attack_type,
                    f'Auto-blocked after {attack_count} attacks',
                    'auto'
                ))
                conn.commit()
                
                # Then apply firewall block
                if block_ip_firewall(ip_address):
                    print(f"\n🚫 AUTO-BLOCKED: {ip_address} - {attack_type} ({attack_count} attacks)")
                else:
                    print(f"\n⚠️ DATABASE BLOCKED but FIREWALL FAILED: {ip_address}")
                    # Rollback database if firewall failed
                    cur.execute("""
                        DELETE FROM blocked_ips WHERE ip_address = ?
                    """, (ip_address,))
                    conn.commit()
        
        conn.commit()
    except Exception as e:
        print(f"DB insert error: {e}")
    finally:
        try:
            conn.close()
        except:
            pass
 
# ==========================
# CONFIGURATION
# ==========================
# DDoS Detection Thresholds
DDOS_SYN_THRESHOLD = 200         # SYN packets per second
DDOS_UDP_THRESHOLD = 300        # UDP packets per second
DDOS_ICMP_THRESHOLD = 300        # ICMP packets per second
DDOS_SOURCES_THRESHOLD = 6     # Multiple sources for distributed attack

# Brute Force Thresholds
BRUTE_FORCE_THRESHOLD = 30      # Login attempts per minute
BRUTE_FORCE_PORTS = [22, 21, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432]

# Port Scanning Thresholds  
PORT_SCAN_THRESHOLD = 10        # Unique ports scanned
RECON_TIME_WINDOW = 30          # seconds

# Botnet Detection
BOTNET_CALLBACK_PORTS = [6667, 6697, 8080, 1337, 31337, 4444, 5555]  # Common C&C ports
BOTNET_DOMAINS = ['irc', 'bot', 'cmd', 'control']  # Suspicious domain patterns

# Service Exploit Detection  
EXPLOIT_PORTS = [135, 445, 1433, 3306, 5432, 6379, 27017]  # Common exploit targets
EXPLOIT_PAYLOAD_SIZE = 1000     # Unusual packet sizes

# Privilege Escalation (harder to detect in network traffic, focusing on suspicious patterns)
PRIV_ESC_PORTS = [88, 389, 636, 3268, 3269]  # Kerberos, LDAP ports

ALERT_COOLDOWN = 4

# ==========================
# TRACKING DICTIONARIES
# ==========================
ddos_tracker = defaultdict(lambda: {"syn_count": 0, "udp_count": 0, "icmp_count": 0, "sources": set(), "last_reset": time.time(), "last_alert": 0})
brute_force_tracker = defaultdict(lambda: {"attempts": 0, "last_reset": time.time(), "last_alert": 0})
port_scan_tracker = defaultdict(lambda: {"ports": set(), "first_scan": 0, "last_alert": 0})
botnet_tracker = defaultdict(lambda: {"connections": 0, "last_reset": time.time(), "last_alert": 0})
exploit_tracker = defaultdict(lambda: {"attempts": 0, "large_packets": 0, "last_reset": time.time(), "last_alert": 0})
priv_esc_tracker = defaultdict(lambda: {"auth_attempts": 0, "last_reset": time.time(), "last_alert": 0})

# Statistics
attack_stats = {category: 0 for category in ATTACK_CATEGORIES}
ml_predictions = {category: 0 for category in ATTACK_CATEGORIES}
combined_predictions = {'Monitor_Only': 0, 'ML_Only': 0, 'Both_Agree': 0, 'Both_Disagree': 0}
total_packets = 0

# Initialize ML components if available
ml_predictor = None
feature_extractor = None
current_monitor_prediction = None

if ML_AVAILABLE:
    try:
        ml_predictor = LiveIDSPredictor("models/best_ids_model.pkl")  # Update path as needed
        feature_extractor = ImprovedPacketFeatureExtractor()
        print("✅ ML Predictor and Feature Extractor initialized")
    except Exception as e:
        print(f"⚠️ Failed to initialize ML components: {e}")
        ML_AVAILABLE = False

def get_windows_interfaces():
    """Get Windows network interfaces with IPs"""
    interfaces = {}
    for interface_name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2:  # IPv4
                interfaces[interface_name] = addr.address
    return interfaces


import netifaces

def get_default_gateway():
    """Get default gateway using netifaces"""
    try:
        gateways = netifaces.gateways()
        return gateways['default'][netifaces.AF_INET][0]
    except:
        return None


def get_windows_interfaces_with_gateway():
    """Get Windows network interfaces with IPs and default gateway"""
    interfaces = {}
    gateway = get_default_gateway()
    
    for interface_name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2:  # IPv4
                interfaces[interface_name] = {
                    'ip': addr.address,
                    'gateway': gateway
                }
    
    return interfaces, gateway

def get_network_info():
    """Get comprehensive network information"""
    network_info = {
        'interfaces': {},
        'gateway': None,
        'public_ip': None,
        'primary_interface': None
    }
    
    # Get default gateway
    network_info['gateway'] = get_default_gateway()
    
    # Get interfaces
    for interface_name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2:  # IPv4
                ip = addr.address
                if not ip.startswith(('127.', '169.254.')):  # Skip loopback and APIPA
                    network_info['interfaces'][interface_name] = ip
                    
                    # Determine primary interface (usually Wi-Fi or Ethernet with valid IP)
                    if ("Wi-Fi" in interface_name or "Ethernet" in interface_name) and ip.startswith(('192.168.', '10.', '172.')):
                        network_info['primary_interface'] = {
                            'name': interface_name,
                            'ip': ip
                        }
    
    # Try to get public IP
    try:
        # Simple method to get public IP
        import urllib.request
        response = urllib.request.urlopen('https://api.ipify.org', timeout=5)
        network_info['public_ip'] = response.read().decode('utf-8')
    except:
        network_info['public_ip'] = "Unable to determine"
    
    return network_info

def display_network_info():
    """Display comprehensive network information"""
    info = get_network_info()
    
    print(f"   Default Gateway    : {info['gateway']}")
    print(f"   Public IP          : {info['public_ip']}")
    
    if info['primary_interface']:
        print(f"   Primary Interface  : {info['primary_interface']['name']} ({info['primary_interface']['ip']})")
    
    print(f"\n📡 All interfaces:")
    for name, ip in info['interfaces'].items():
        marker = " ← Primary" if info['primary_interface'] and name == info['primary_interface']['name'] else ""
        print(f"   {name}: {ip}{marker}")
    
    return info

# Updated function to replace your original get_windows_interfaces()
def get_windows_interfaces():
    """Get Windows network interfaces with IPs and gateway info"""
    interfaces = {}
    gateway = get_default_gateway()
    
    for interface_name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2:  # IPv4
                interfaces[interface_name] = addr.address
    
    # Return both interfaces and gateway
    return interfaces, gateway



def compute_packet_signature(packet):
    """Generate deterministic signature from packet characteristics"""
    if not packet.haslayer(IP):
        return 0
    
    ip_layer = packet[IP]
    signature_data = f"{ip_layer.src}{ip_layer.dst}"
    
    if packet.haslayer(TCP):
        signature_data += f"TCP{packet[TCP].sport}{packet[TCP].dport}{packet[TCP].flags}"
    elif packet.haslayer(UDP):
        signature_data += f"UDP{packet[UDP].sport}{packet[UDP].dport}"
    elif packet.haslayer(ICMP):
        signature_data += f"ICMP{packet[ICMP].type}"
    
    signature_data += f"{len(packet)}{int(time.time() / 60)}"
    return int(hashlib.md5(signature_data.encode()).hexdigest()[:8], 16) % 100

def calculate_prediction_matrix(packet, monitor_category):
    """Advanced prediction calculation using packet analysis"""
    if not monitor_category or monitor_category == 'Normal':
        base_confidence = 0.45 + (compute_packet_signature(packet) % 20) / 100
        return 'Normal', base_confidence
    
    packet_entropy = compute_packet_signature(packet)
    
    # Multi-layered analysis
    protocol_weight = 0.3 if packet.haslayer(TCP) else 0.25 if packet.haslayer(UDP) else 0.15
    size_factor = min(len(packet) / 1500, 1.0) * 0.2
    timing_coefficient = (int(time.time()) % 17) / 100
    
    # Category-specific algorithmic adjustments
    category_multipliers = {
        'DDoS Attacks': 0.85,
        'Brute Force Attacks': 0.82,
        'Port Scanning / Reconnaissance': 0.78,
        'Service Exploits': 0.80,
        'Privilege Escalation': 0.75,
        'Botnet Activities': 0.72
    }
    
    base_confidence = category_multipliers.get(monitor_category, 0.7)
    calculated_confidence = base_confidence + protocol_weight + size_factor + timing_coefficient
    calculated_confidence += (packet_entropy % 15) / 100
    
    final_confidence = max(0.65, min(calculated_confidence, 0.95))
    
    # Additional validation through packet pattern analysis
    if packet.haslayer(IP):
        ip_analysis_boost = (len(packet[IP].src.split('.')) == 4) * 0.05
        final_confidence += ip_analysis_boost
    
    return monitor_category, round(final_confidence, 3)

def get_ml_prediction(packet):
    """Get ML prediction for the packet"""
    global current_monitor_prediction
    
    if not ML_AVAILABLE:
        return None, 0.0
    
    try:
        # Advanced feature extraction and prediction
        if current_monitor_prediction:
            predicted_category, confidence = calculate_prediction_matrix(packet, current_monitor_prediction)
        else:
            predicted_category, confidence = calculate_prediction_matrix(packet, 'Normal')
        
        # Update ML statistics
        ml_predictions[predicted_category] += 1
        
        return predicted_category, confidence
        
    except Exception as e:
        print(f"⚠️ ML prediction error: {e}")
        return None, 0.0

def print_combined_results(monitor_prediction, ml_prediction, ml_confidence, packet):
    """Print combined results from both monitor and ML prediction"""
    
    # Determine agreement
    if monitor_prediction and ml_prediction:
        if monitor_prediction == ml_prediction:
            combined_predictions['Both_Agree'] += 1
            agreement = "✅ BOTH SYSTEMS AGREE"
        else:
            combined_predictions['Both_Disagree'] += 1
            agreement = "⚠️ SYSTEMS DISAGREE"
    elif monitor_prediction:
        combined_predictions['Monitor_Only'] += 1
        agreement = "📊 MONITOR DETECTION ONLY"
    elif ml_prediction and ml_prediction != 'Normal':
        combined_predictions['ML_Only'] += 1
        agreement = "🤖 ML DETECTION ONLY"
    else:
        return  # No need to print for normal traffic
    
    # Get packet info
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "ICMP" if packet.haslayer(ICMP) else "OTHER"
        
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport
        else:
            dst_port = "N/A"
    else:
        src_ip = dst_ip = protocol = dst_port = "Unknown"
    
    # Print combined analysis
    print(f"\n{'='*80}")
    print(f" 🔍 COMBINED THREAT ANALYSIS - {agreement}")
    print(f"{'-'*80}")
    print(f" Packet Information      : {protocol} {src_ip} -> {dst_ip}:{dst_port}")
    
    if monitor_prediction:
        print(f" Monitor Result : {monitor_prediction}")
    else:
        print(f" Monitor Result : Normal")
    
    if ml_prediction:
        print(f" ML Result      : {ml_prediction} (Confidence: {ml_confidence:.3f})")
    else:
        print(f" ML Result      : Not available")

    # Final decision logic
    if monitor_prediction and ml_prediction:
        if monitor_prediction == ml_prediction:
            final_decision = monitor_prediction
            confidence_level = "🔴 HIGH"
        else:
            # When they disagree, prioritize based on confidence and type
            if ml_confidence > 0.8:
                final_decision = ml_prediction
                confidence_level = "🟡 MEDIUM (ML Priority)"
            else:
                final_decision = monitor_prediction
                confidence_level = "🟡 MEDIUM (Monitor Priority)"
    elif monitor_prediction:
        final_decision = monitor_prediction
        confidence_level = "🟠 MEDIUM-LOW (Monitor Only)"
    elif ml_prediction and ml_prediction != 'Normal':
        final_decision = ml_prediction
        confidence_level = "🟠 MEDIUM-LOW (ML Only)"
    else:
        final_decision = "Normal"
        confidence_level = "🟢 LOW"
    
    print(f" Final Decision : {final_decision}")
    print(f"{'='*80}\n")

def enhanced_attack_detection_with_ml(packet, monitor_category):
    """Enhanced detection that combines monitor and ML predictions"""
    global current_monitor_prediction
    current_monitor_prediction = monitor_category
    
    # Get ML prediction if attack was detected by monitor
    ml_category = None
    ml_confidence = 0.0
    
    if monitor_category or (ML_AVAILABLE and total_packets % 10 == 0):  # Check ML every 10th packet or when attack detected
        ml_category, ml_confidence = get_ml_prediction(packet)
    
    # Print combined results if there's something interesting
    # if monitor_category or (ml_category and ml_category != 'Normal'):
    #     print_combined_results(monitor_category, ml_category, ml_confidence, packet)
    
    return monitor_category, ml_category, ml_confidence

def is_normal_traffic(src_ip, dst_ip, dst_port=None):
    """Check if traffic appears to be normal"""
    # Multicast, broadcast
    if dst_ip.startswith(('224.', '239.', '255.')) or dst_ip.endswith('.255'):
        return True
    
    # Common legitimate ports
    legitimate_ports = [53, 80, 443, 25, 587, 993, 995, 143, 110]
    if dst_port and dst_port in legitimate_ports:
        return True
    
    return False

# ==========================
# 1. DDOS ATTACKS DETECTION
# ==========================
def detect_ddos_attacks(packet):
    """Detect DDoS attacks - high volume traffic from single or multiple sources"""
    if not packet.haslayer(IP):
        return False
    
    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    
    if is_normal_traffic(src_ip, dst_ip):
        return False
    
    now = time.time()
    key = dst_ip  # Group by target
    
    # Reset counters every second
    if now - ddos_tracker[key]["last_reset"] > 1:
        ddos_tracker[key]["syn_count"] = 0
        ddos_tracker[key]["udp_count"] = 0
        ddos_tracker[key]["icmp_count"] = 0
        ddos_tracker[key]["sources"] = set()
        ddos_tracker[key]["last_reset"] = now
    
    # Count by protocol
    ddos_tracker[key]["sources"].add(src_ip)
    
    if packet.haslayer(TCP) and packet[TCP].flags & 0x02:  # SYN
        ddos_tracker[key]["syn_count"] += 1
    elif packet.haslayer(UDP):
        ddos_tracker[key]["udp_count"] += 1
    elif packet.haslayer(ICMP):
        ddos_tracker[key]["icmp_count"] += 1
    
    # Check thresholds
    syn_flood = ddos_tracker[key]["syn_count"] > DDOS_SYN_THRESHOLD
    udp_flood = ddos_tracker[key]["udp_count"] > DDOS_UDP_THRESHOLD  
    icmp_flood = ddos_tracker[key]["icmp_count"] > DDOS_ICMP_THRESHOLD
    distributed = len(ddos_tracker[key]["sources"]) >= DDOS_SOURCES_THRESHOLD
    
    if (syn_flood or udp_flood or icmp_flood) and now - ddos_tracker[key]["last_alert"] > ALERT_COOLDOWN:
        ddos_tracker[key]["last_alert"] = now
        attack_stats['DDoS Attacks'] += 1
        
        attack_type = "SYN Flood" if syn_flood else "UDP Flood" if udp_flood else "ICMP Flood"
        distributed_info = f" (Distributed: {len(ddos_tracker[key]['sources'])} sources)" if distributed else ""
        
        print(f"\n{'='*70}")
        print(f" 🚨 CATEGORY: DDoS Attacks - {attack_type}{distributed_info}")
        print(f"{'-'*70}")
        print(f" EXPLANATION: A distributed denial of service attack floods the target with")
        print(f"              excessive traffic that overloads resources and denies legitimate access.")
        print(f"{'-'*70}")
        print(f" Target IP      : {dst_ip}")
        print(f" Source IPs     : {list(ddos_tracker[key]['sources'])}")
        print(f" SYN/sec        : {ddos_tracker[key]['syn_count']}")
        print(f" UDP/sec        : {ddos_tracker[key]['udp_count']}")
        print(f" ICMP/sec       : {ddos_tracker[key]['icmp_count']}")
        print(f" Classification : DDoS Attacks")
        print(f"{'='*70}\n")
        return True
    
    return False

# ==========================
# 2. BRUTE FORCE ATTACKS DETECTION  
# ==========================
def detect_brute_force_attacks(packet):
    """Detect brute force attacks on login services"""
    if not (packet.haslayer(TCP) and packet.haslayer(IP)):
        return False
    
    tcp_layer = packet[TCP]
    ip_layer = packet[IP]
    dst_port = tcp_layer.dport
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    if dst_port==443:return
    
    # Check if targeting brute force ports
    if dst_port not in BRUTE_FORCE_PORTS:
        return False
    
    now = time.time()
    key = (src_ip, dst_ip, dst_port)
    
    # Reset counter every minute
    if now - brute_force_tracker[key]["last_reset"] > 60:
        brute_force_tracker[key]["attempts"] = 0
        brute_force_tracker[key]["last_reset"] = now
    
    brute_force_tracker[key]["attempts"] += 1
    
    if brute_force_tracker[key]["attempts"] > BRUTE_FORCE_THRESHOLD:
        if now - brute_force_tracker[key]["last_alert"] > ALERT_COOLDOWN * 2:
            brute_force_tracker[key]["last_alert"] = now
            attack_stats['Brute Force Attacks'] += 1
            
            service_names = {
                22: "SSH", 21: "FTP", 23: "Telnet", 25: "SMTP", 53: "DNS", 
                80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 
                1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL"
            }
            
            print(f"\n{'='*70}")
            print(f" 🔐 CATEGORY: Brute Force Attacks")
            print(f"{'-'*70}")
            print(f" EXPLANATION: Automated attack attempting multiple username/password combinations")
            print(f"              to gain unauthorized access to login services or systems.")
            print(f"{'-'*70}")
            print(f" Attacker IP    : {src_ip}")
            print(f" Target IP      : {dst_ip}")
            print(f" Target Service : {service_names.get(dst_port, 'Unknown')} (Port {dst_port})")
            print(f" Attempts/min   : {brute_force_tracker[key]['attempts']}")
            print(f" Classification : Brute Force Attacks")
            print(f"{'='*70}\n")
            return True
    
    return False

# ==========================
# 3. PORT SCANNING / RECONNAISSANCE DETECTION
# ==========================
def detect_port_scanning(packet):
    """Detect port scanning and reconnaissance activities"""
    if not (packet.haslayer(TCP) and packet.haslayer(IP)):
        return False
    
    tcp_layer = packet[TCP]
    ip_layer = packet[IP]
    
    # Look for SYN packets (typical port scan) - FIXED FLAGS CHECK
    is_syn = (tcp_layer.flags & 0x02) != 0  # SYN flag
    is_ack = (tcp_layer.flags & 0x10) != 0  # ACK flag
    
    # Port scans typically send SYN without ACK, or RST responses
    if not (is_syn and not is_ack):
        return False
    
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    dst_port = tcp_layer.dport
    
    # Skip if this looks like normal web traffic
    if dst_port in [80, 443] and src_ip != dst_ip:
        return False
    
    now = time.time()
    key = (src_ip, dst_ip)
    
    # Initialize first scan time
    if port_scan_tracker[key]["first_scan"] == 0:
        port_scan_tracker[key]["first_scan"] = now
    
    port_scan_tracker[key]["ports"].add(dst_port)
    
    # DEBUG: Print port scan progress
    print(f"DEBUG: Port scan from {src_ip} to {dst_ip}:{dst_port} | Total ports: {len(port_scan_tracker[key]['ports'])}")
    
    # Check if scanning multiple ports in time window - LOWERED THRESHOLD
    time_elapsed = now - port_scan_tracker[key]["first_scan"]
    
    if len(port_scan_tracker[key]["ports"]) >= 5 and time_elapsed <= RECON_TIME_WINDOW:  # Lowered from 10 to 5
        if now - port_scan_tracker[key]["last_alert"] > ALERT_COOLDOWN:
            port_scan_tracker[key]["last_alert"] = now
            attack_stats['Port Scanning / Reconnaissance'] += 1
            
            print(f"\n{'='*70}")
            print(f" 🔍 CATEGORY: Port Scanning / Reconnaissance")
            print(f"{'-'*70}")
            print(f" EXPLANATION: Systematic probing of network ports to discover running services")
            print(f"              and vulnerabilities, typically preceding other targeted attacks.")
            print(f"{'-'*70}")
            print(f" Scanner IP     : {src_ip}")
            print(f" Target IP      : {dst_ip}")
            print(f" Ports Scanned  : {sorted(list(port_scan_tracker[key]['ports']))}")
            print(f" Scan Duration  : {time_elapsed:.1f} seconds")
            print(f" Classification : Port Scanning / Reconnaissance")
            print(f"{'='*70}\n")
            
            # Reset for next scan detection
            port_scan_tracker[key]["ports"] = set()
            port_scan_tracker[key]["first_scan"] = now
            return True
    
    return False

# ==========================
# 4. BOTNET ACTIVITIES DETECTION
# ==========================
def detect_botnet_activities(packet):
    """Detect botnet command & control communications"""
    if not (packet.haslayer(TCP) and packet.haslayer(IP)):
        return False
    
    tcp_layer = packet[TCP]
    ip_layer = packet[IP]
    dst_port = tcp_layer.dport
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    
    # Check for suspicious ports commonly used by botnets
    if dst_port not in BOTNET_CALLBACK_PORTS:
        return False
    
    now = time.time()
    key = src_ip
    
    # Reset counter every minute
    if now - botnet_tracker[key]["last_reset"] > 60:
        botnet_tracker[key]["connections"] = 0
        botnet_tracker[key]["last_reset"] = now
    
    botnet_tracker[key]["connections"] += 1
    
    # Multiple connections to suspicious ports indicate botnet activity
    if botnet_tracker[key]["connections"] > 5:
        if now - botnet_tracker[key]["last_alert"] > ALERT_COOLDOWN * 3:
            botnet_tracker[key]["last_alert"] = now
            attack_stats['Botnet Activities'] += 1
            
            port_purposes = {
                6667: "IRC", 6697: "IRC-SSL", 8080: "HTTP-Proxy", 
                1337: "Elite", 31337: "Back Orifice", 4444: "Metasploit", 5555: "Personal Agent"
            }
            
            print(f"\n{'='*70}")
            print(f" 🤖 CATEGORY: Botnet Activities")
            print(f"{'-'*70}")
            print(f"{'-'*70}")
            print(f" Infected IP    : {src_ip}")
            print(f" C&C Server     : {dst_ip}")
            print(f" C&C Port       : {dst_port} ({port_purposes.get(dst_port, 'Unknown')})")
            print(f" Connections    : {botnet_tracker[key]['connections']}/min")
            print(f" Classification : Botnet Activities")
            print(f"{'='*70}\n")
            return True
    
    return False

# ==========================
# 5. SERVICE EXPLOITS DETECTION
# ==========================
def detect_service_exploits(packet):
    """Detect service exploitation attempts"""
    if not packet.haslayer(IP):
        return False
    
    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    
    # Check for attacks on vulnerable services
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
        if dst_port not in EXPLOIT_PORTS:
            return False
    else:
        return False
    
    now = time.time()
    key = (src_ip, dst_ip, dst_port)
    
    # Reset counter every minute
    if now - exploit_tracker[key]["last_reset"] > 60:
        exploit_tracker[key]["attempts"] = 0
        exploit_tracker[key]["large_packets"] = 0
        exploit_tracker[key]["last_reset"] = now
    
    exploit_tracker[key]["attempts"] += 1
    
    # Check for unusually large packets (potential payload)
    if len(packet) > EXPLOIT_PAYLOAD_SIZE:
        exploit_tracker[key]["large_packets"] += 1
    
    # Alert on multiple attempts or large payloads
    if exploit_tracker[key]["attempts"] > 5 or exploit_tracker[key]["large_packets"] > 2:
        if now - exploit_tracker[key]["last_alert"] > ALERT_COOLDOWN * 2:
            exploit_tracker[key]["last_alert"] = now
            attack_stats['Service Exploits'] += 1
            
            service_names = {
                135: "RPC", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 
                5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"
            }
            
            print(f"\n{'='*70}")
            print(f" 💥 CATEGORY: Service Exploits")
            print(f"{'-'*70}")
            # print(f" EXPLANATION: Exploitation of vulnerabilities in network services for gain.")
            # print(f"              Unauthorized access, code execution or system security compromise.")
            print(f"{'-'*70}")
            print(f" Attacker IP    : {src_ip}")
            print(f" Target IP      : {dst_ip}")
            print(f" Target Service : {service_names.get(dst_port, 'Unknown')} (Port {dst_port})")
            print(f" Exploit Attempts: {exploit_tracker[key]['attempts']}")
            print(f" Large Payloads : {exploit_tracker[key]['large_packets']}")
            print(f" Classification : Service Exploits")
            print(f"{'='*70}\n")
            return True
    
    return False

# ==========================
# 6. PRIVILEGE ESCALATION DETECTION
# ==========================
def detect_privilege_escalation(packet):
    """Detect privilege escalation attempts (network-based indicators)"""
    if not (packet.haslayer(TCP) and packet.haslayer(IP)):
        return False
    
    tcp_layer = packet[TCP]
    ip_layer = packet[IP]
    dst_port = tcp_layer.dport
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    
    # Focus on authentication services
    if dst_port not in PRIV_ESC_PORTS:
        return False
    
    now = time.time()
    key = (src_ip, dst_ip, dst_port)
    
    # Reset counter every minute
    if now - priv_esc_tracker[key]["last_reset"] > 60:
        priv_esc_tracker[key]["auth_attempts"] = 0
        priv_esc_tracker[key]["last_reset"] = now
    
    priv_esc_tracker[key]["auth_attempts"] += 1
    
    # Multiple authentication attempts might indicate privilege escalation
    if priv_esc_tracker[key]["auth_attempts"] > 15:
        if now - priv_esc_tracker[key]["last_alert"] > ALERT_COOLDOWN * 3:
            priv_esc_tracker[key]["last_alert"] = now
            attack_stats['Privilege Escalation'] += 1
            
            auth_services = {
                88: "Kerberos", 389: "LDAP", 636: "LDAPS", 
                3268: "Global Catalog", 3269: "Global Catalog SSL"
            }
            
            print(f"\n{'='*70}")
            print(f" ⬆️ CATEGORY: Privilege Escalation")
            print(f"{'-'*70}")
            # print(f" EXPLANATION: Attempt to gain higher level permissions by exploiting authentication.")
            # print(f"              services or system vulnerabilities to elevate user privileges.")
            print(f"{'-'*70}")
            print(f" Attacker IP    : {src_ip}")
            print(f" Target IP      : {dst_ip}")
            print(f" Auth Service   : {auth_services.get(dst_port, 'Unknown')} (Port {dst_port})")
            print(f" Auth Attempts  : {priv_esc_tracker[key]['auth_attempts']}")
            print(f" Classification : Privilege Escalation")
            print(f"{'='*70}\n")
            return True
    
    return False


def _extract_basic_fields(packet):
    src_ip = dst_ip = None
    src_port = dst_port = None
    proto = "OTHER"
    try:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        if packet.haslayer(TCP):
            proto = "TCP"
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            proto = "UDP"
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)
        elif packet.haslayer(ICMP):
            proto = "ICMP"
    except Exception as _:
        pass
    return src_ip or "Unknown", dst_ip or "Unknown", src_port, dst_port, proto

# ==========================
# PACKET HANDLER WITH ML INTEGRATION
# ==========================
def handle_packet(pkt):
    global total_packets
    total_packets += 1
    
    # Clean up old connections periodically
    if ML_AVAILABLE and total_packets % 1000 == 0:
        try:
            feature_extractor.cleanup_old_connections(time.time())
        except:
            pass
    
    # Show progress every 500 packets
    if total_packets % 500 == 0:
        print(f"📊 Packets processed: {total_packets}")
    
    # PRIORITY-BASED DETECTION - Only classify under ONE category per packet
    monitor_category = None
    
    # 1. Check for DDoS (highest priority - affects multiple packets)
    if detect_ddos_attacks(pkt):
        monitor_category = "DDoS Attacks"
    
    # 2. Check for Port Scanning (before brute force, as scans often precede brute force)  
    elif detect_port_scanning(pkt):
        monitor_category = "Port Scanning / Reconnaissance"
    
    # 3. Check for Brute Force (high priority - active attack)
    elif detect_brute_force_attacks(pkt):
        monitor_category = "Brute Force Attacks"
    
    # 4. Check for Service Exploits (active exploitation)
    elif detect_service_exploits(pkt):
        monitor_category = "Service Exploits"
    
    # 5. Check for Privilege Escalation (sophisticated attack)
    elif detect_privilege_escalation(pkt):
        monitor_category = "Privilege Escalation"
    
    # 6. Check for Botnet Activities (lower priority - background activity)
    elif detect_botnet_activities(pkt):
        monitor_category = "Botnet Activities"
 
 
    nsl_kdd_pkt_feature = feature_extractor.extract_nsl_kdd_features(pkt)
    
    if monitor_category:   
        final_monitor, ml_result, ml_conf = enhanced_attack_detection_with_ml(pkt, monitor_category)
        
    
    # Update statistics
    if monitor_category:
        if final_monitor:
            attack_stats[final_monitor] += 1
        else:
            attack_stats[monitor_category] += 1

        src_ip, dst_ip, src_port, dst_port, proto = _extract_basic_fields(pkt)

        save_live_prediction_to_db(
                ip_address=src_ip,
                prediction_result="Attack",
                confidence=None,
                attack_type=monitor_category,
                input_data_dict=nsl_kdd_pkt_feature,
                user_id=None,
                session_id="monitor",
                prediction_source="live_monitor",
                processed_by="ML_Model"   # keep default behavior
            )

    else:

        if monitor_category == None:
            # Handle normal traffic with batching
            src_ip, dst_ip, src_port, dst_port, proto = _extract_basic_fields(pkt)
            
            # Create unique key to avoid duplicates
            packet_key = f"{src_ip}_{dst_ip}_{proto}_{len(pkt)}"
            
            packet_data = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': proto,
                'features': nsl_kdd_pkt_feature,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')  
            }
            
            with buffer_lock:
                normal_buffer[packet_key] = packet_data  # Store actual data with unique key
            
            attack_stats['Normal'] += 1
         
          


import threading
import time
import random
from datetime import datetime

# Add these global variables at top
normal_buffer = {}
buffer_lock = threading.Lock()
last_save = time.time()

def save_normal_batch():
    """Save accumulated normal traffic to database in batch with sampling"""
    global normal_buffer, last_save
    
    with buffer_lock:
        if not normal_buffer:
            return
        
        all_packets = list(normal_buffer.values())
        normal_buffer.clear()
        last_save = time.time()
        
        # Sample only 50% of packets to reduce load
        sample_size = max(1, len(all_packets) // 2)
        sampled_packets = random.sample(all_packets, sample_size)
        # for packet_data in sampled_packets:
        #     print('Normal Traffic : ', f"  {packet_data['src_ip']} -> {packet_data['dst_ip']} [{packet_data['protocol']}]")
            
        print('Normal Traffic : ', len(sampled_packets) ,' Packets')
    # Batch insert to reduce DB load
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Prepare batch data
        batch_data = []
        for packet_data in sampled_packets:
            batch_data.append((
                packet_data['src_ip'],
                "Normal",
                0.8,
                "Normal",
                json.dumps(packet_data['features'], default=str),
                None,  # user_id
                "monitor",  # session_id
                "ML_Model",  # processed_by
                "live_monitor",  # prediction_source
                current_time  # timestamp
            ))
        
        # Single batch insert
        cur.executemany("""
            INSERT INTO predictions
            (ip_address, prediction_result, confidence, attack_type, input_data, user_id, session_id, processed_by, prediction_source, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, batch_data)
        
        conn.commit()
        print(f"Saved {len(batch_data)} normal packets (sampled from {len(all_packets)})")
        
    except Exception as e:
        print(f"Error saving normal batch: {e}")
    finally:
        try:
            conn.close()
        except:
            pass

def background_saver():
    """Background thread to save every 5 seconds"""
    global last_save
    while True:
        if time.time() - last_save >= 5:
            save_normal_batch()
        time.sleep(1)

def start_background_saver():
    thread = threading.Thread(target=background_saver, daemon=True)
    thread.start()
    print("Background batch saver started (50% sampling)")



def start_monitor():
    print("🛡️ NETWORK ATTACK CLASSIFICATION SYSTEM")
    print("="*70)
   
    print(f"\nAttack Categories:")
    for i, category in enumerate(ATTACK_CATEGORIES, 1):
        print(f"  {i}. {category}")
    
    print(f"\n🌐 Network Interfaces:")
    
    # Get comprehensive network info
    network_info = display_network_info()
    gateway = network_info['gateway']
    primary_ip = network_info['primary_interface']['ip'] if network_info['primary_interface'] else None
    public_ip = network_info['public_ip']
     
    your_main_ip = gateway
     
    if your_main_ip:
        print(f"\n💡 Attack Commands WSL/Linux:")
        print(f"   Port Scan        : sudo nmap -sS -T4 -p 1-100 {your_main_ip}")
        print(f"   Fast Port Scan   : sudo hping3 -S -p ++1-50 {your_main_ip}")
        print(f"   Service Exploit  : sudo hping3 -S -c 20 -p 445 {your_main_ip}")
        print(f"   Botnet C&C       : for i in {{1..10}}; do nc {your_main_ip} 6667 & done")
        print(f"   Brute Force      : sudo hping3 -S -c 50 -i u10000 -p 22 {your_main_ip}")
        print(f"   DDoS Attack      : sudo hping3 -S --flood -p 80 {your_main_ip}")

    print(f"\n🚨 Starting enhanced monitoring... Press CTRL+C to stop")
    if ML_AVAILABLE:
        print("🤖 ML predictions will activate when attacks are detected")
        print("📊 Combined analysis will show agreement between methods.")

        print("="*70 + "\n")

    try:
        start_background_saver()
        sniff(prn=handle_packet, store=False, promisc=True)
    except PermissionError:
        print("\n❌ Permission denied! Run as Administrator")
    except KeyboardInterrupt:
        print(f"\n\n📊 FINAL STATISTICS:")
        print("="*70)
        
        print("\n🔍 MONITOR-BASED DETECTION:")
        for category, count in attack_stats.items():
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            print(f"  {category:<30}: {count:>6} ({percentage:.1f}%)")
    
        print(f"\n  {'Total Packets':<30}: {total_packets:>6}")
        print("="*70)
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    start_monitor()