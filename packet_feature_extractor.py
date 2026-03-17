from scapy.all import IP, TCP, UDP, ICMP
from collections import defaultdict, Counter
import time
import numpy as np

class ImprovedPacketFeatureExtractor:
    def __init__(self):
        """Extract meaningful NSL-KDD features from network packets"""
        
        # Connection tracking for flow-based features
        self.connections = defaultdict(lambda: {
            'start_time': 0,
            'duration': 0,
            'src_bytes': 0,
            'dst_bytes': 0,
            'packets_sent': 0,
            'packets_received': 0,
            'flags': set(),
            'services': set(),
            'last_update': 0,
            'wrong_fragments': 0,
            'urgent_packets': 0,
            'login_attempts': 0,
            'failed_logins': 0,
            'logged_in': False,
            'compromised_conditions': 0,
            'root_access': False,
            'file_creations': 0,
            'shells_opened': 0,
            'access_files': 0
        })
        
        # Host-based tracking (for dst_host_* features)
        self.host_stats = defaultdict(lambda: {
            'connections': [],
            'services': set(),
            'error_connections': 0,
            'successful_connections': 0,
            'same_src_port_connections': 0
        })
        
        # Service tracking for current time window
        self.service_connections = defaultdict(list)  # service -> [(timestamp, src_ip, dst_ip)]
        self.connection_window = defaultdict(list)    # (src_ip, dst_ip) -> [timestamps]
        
        # Service mapping - more comprehensive
        self.service_map = {
            20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 67: 'dhcp', 68: 'dhcp', 69: 'tftp', 79: 'finger',
            80: 'http', 110: 'pop3', 111: 'rpc', 119: 'nntp', 123: 'ntp',
            135: 'epmap', 139: 'netbios-ssn', 143: 'imap', 161: 'snmp',
            389: 'ldap', 443: 'https', 445: 'microsoft-ds', 993: 'imaps',
            995: 'pop3s', 1433: 'mssql', 1521: 'oracle', 3306: 'mysql',
            3389: 'rdp', 5432: 'postgresql', 6379: 'redis', 27017: 'mongodb'
        }
        
        # Protocol mapping
        self.protocol_map = {'tcp': 0, 'udp': 1, 'icmp': 2}
        
        # Flag mapping for TCP
        self.flag_map = {
            'S': 'SYN', 'A': 'ACK', 'F': 'FIN', 'R': 'RST', 
            'P': 'PSH', 'U': 'URG', 'E': 'ECE', 'C': 'CWR'
        }
        
        # Time windows
        self.time_window = 2  # seconds for connection counting
        self.host_window = 100  # connections for host-based features
        
    def get_service_name(self, port, protocol='tcp'):
        """Get service name from port"""
        if port in self.service_map:
            return self.service_map[port]
        elif port < 1024:
            return f'reserved_{port}'
        elif port > 49152:
            return 'private'
        else:
            return f'port_{port}'
    
    def get_tcp_flags(self, tcp_layer):
        """Extract TCP flags information"""
        flags = tcp_layer.flags
        flag_names = []
        
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')
        if flags & 0x40: flag_names.append('ECE')
        if flags & 0x80: flag_names.append('CWR')
        
        return flag_names
    
    def analyze_connection_state(self, packet, conn_key):
        """Analyze connection state and patterns"""
        conn = self.connections[conn_key]
        current_time = time.time()
        
        # Basic connection info
        if conn['start_time'] == 0:
            conn['start_time'] = current_time
        
        conn['last_update'] = current_time
        conn['duration'] = current_time - conn['start_time']
        
        # Packet size analysis
        packet_size = len(packet)
        if packet.haslayer(IP):
            if packet[IP].src == conn_key[0]:  # Outgoing packet
                conn['src_bytes'] += packet_size
                conn['packets_sent'] += 1
            else:  # Incoming packet
                conn['dst_bytes'] += packet_size
                conn['packets_received'] += 1
        
        # TCP-specific analysis
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            flags = self.get_tcp_flags(tcp_layer)
            conn['flags'].update(flags)
            
            # Fragment analysis
            if hasattr(packet[IP], 'frag') and packet[IP].frag > 0:
                conn['wrong_fragments'] += 1
            
            # Urgent data
            if 'URG' in flags:
                conn['urgent_packets'] += 1
            
            # Service analysis
            service = self.get_service_name(tcp_layer.dport)
            conn['services'].add(service)
            
            # Login attempt heuristics
            if service in ['ssh', 'ftp', 'telnet', 'rdp']:
                # Heuristic: Multiple packets to login services
                if conn['packets_sent'] > 3:
                    conn['login_attempts'] += 1
                
                # Failed login heuristic: RST after attempts
                if 'RST' in flags and conn['login_attempts'] > 0:
                    conn['failed_logins'] += 1
                elif 'ACK' in flags and 'PSH' in flags:
                    conn['logged_in'] = True
            
            # Root shell heuristic
            if service == 'ssh' and packet_size > 100 and conn['logged_in']:
                conn['root_access'] = True
            
            # File creation heuristic
            if service in ['ftp', 'http', 'https'] and 'PSH' in flags:
                conn['file_creations'] += 1
            
            # Shell access heuristic
            if service in ['ssh', 'telnet'] and conn['logged_in']:
                conn['shells_opened'] += 1
    
    def calculate_connection_counts(self, conn_key, current_time):
        """Calculate connection-based features"""
        src_ip, dst_ip, dst_port, protocol = conn_key
        time_threshold = current_time - self.time_window
        
        # Clean old timestamps
        for key in list(self.connection_window.keys()):
            self.connection_window[key] = [
                t for t in self.connection_window[key] if t > time_threshold
            ]
        
        # Add current connection
        self.connection_window[conn_key].append(current_time)
        
        # Count connections to same destination
        same_host_conns = []
        for key, timestamps in self.connection_window.items():
            if key[1] == dst_ip:  # Same destination IP
                same_host_conns.extend([t for t in timestamps if t > time_threshold])
        
        count = len(same_host_conns)
        
        # Count connections to same service
        same_service_conns = []
        service_name = self.get_service_name(dst_port)
        
        for key, timestamps in self.connection_window.items():
            key_service = self.get_service_name(key[2])
            if key_service == service_name:
                same_service_conns.extend([t for t in timestamps if t > time_threshold])
        
        srv_count = len(same_service_conns)
        
        return count, srv_count
    
    def calculate_error_rates(self, conn_key, count, srv_count):
        """Calculate error rates based on connection patterns"""
        src_ip, dst_ip, dst_port, protocol = conn_key
        
        # Get connection info
        conn = self.connections[conn_key]
        flags = conn['flags']
        
        # Simple error rate calculation
        # SYN without ACK might indicate connection errors
        has_syn = 'SYN' in flags
        has_ack = 'ACK' in flags
        has_rst = 'RST' in flags
        
        # Estimate error rates
        serror_rate = 0.0
        if has_syn and has_rst:
            serror_rate = 0.3  # Connection refused/reset
        elif has_syn and not has_ack and conn['duration'] > 3:
            serror_rate = 0.2  # No response
        
        # Service error rate
        srv_serror_rate = serror_rate  # Simplified
        
        # REJ error rates (connection rejected)
        rerror_rate = 0.0
        srv_rerror_rate = 0.0
        
        if has_rst:
            rerror_rate = 0.1
            srv_rerror_rate = 0.1
        
        return serror_rate, srv_serror_rate, rerror_rate, srv_rerror_rate
    
    def calculate_host_features(self, dst_ip, current_time):
        """Calculate destination host-based features"""
        time_threshold = current_time - 100  # 100 second window
        
        # Get recent connections to this host
        host_connections = []
        host_services = set()
        same_src_port = 0
        
        for conn_key, conn in self.connections.items():
            if (conn_key[1] == dst_ip and 
                conn['last_update'] > time_threshold):
                host_connections.append((conn_key, conn))
                host_services.add(self.get_service_name(conn_key[2]))
        
        if not host_connections:
            return {
                'dst_host_count': 1,
                'dst_host_srv_count': 1,
                'dst_host_same_srv_rate': 1.0,
                'dst_host_diff_srv_rate': 0.0,
                'dst_host_same_src_port_rate': 0.0,
                'dst_host_srv_diff_host_rate': 0.0,
                'dst_host_serror_rate': 0.0,
                'dst_host_srv_serror_rate': 0.0,
                'dst_host_rerror_rate': 0.0,
                'dst_host_srv_rerror_rate': 0.0
            }
        
        # Calculate host statistics
        dst_host_count = min(len(host_connections), self.host_window)
        dst_host_srv_count = len(host_services)
        
        # Service distribution
        same_srv_rate = dst_host_srv_count / max(dst_host_count, 1)
        diff_srv_rate = 1.0 - same_srv_rate if same_srv_rate < 1.0 else 0.0
        
        # Source port analysis
        src_ports = [conn_key[0] for conn_key, conn in host_connections]
        port_counts = Counter(src_ports)
        most_common_port_count = port_counts.most_common(1)[0][1] if port_counts else 1
        same_src_port_rate = most_common_port_count / max(dst_host_count, 1)
        
        # Service host diversity (simplified)
        srv_diff_host_rate = min(0.1 * len(host_services), 1.0)
        
        # Error rates for host
        error_connections = 0
        for conn_key, conn in host_connections:
            if 'RST' in conn['flags'] or ('SYN' in conn['flags'] and 'ACK' not in conn['flags']):
                error_connections += 1
        
        error_rate = error_connections / max(dst_host_count, 1)
        
        return {
            'dst_host_count': dst_host_count,
            'dst_host_srv_count': dst_host_srv_count,
            'dst_host_same_srv_rate': same_srv_rate,
            'dst_host_diff_srv_rate': diff_srv_rate,
            'dst_host_same_src_port_rate': same_src_port_rate,
            'dst_host_srv_diff_host_rate': srv_diff_host_rate,
            'dst_host_serror_rate': error_rate,
            'dst_host_srv_serror_rate': error_rate,
            'dst_host_rerror_rate': error_rate * 0.5,
            'dst_host_srv_rerror_rate': error_rate * 0.5
        }
    
    def extract_nsl_kdd_features(self, packet):
        """Extract comprehensive NSL-KDD features from packet"""
        if not packet.haslayer(IP):
            return None
        
        ip_layer = packet[IP]
        current_time = time.time()
        
        # Basic packet info
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        # Protocol and ports
        if packet.haslayer(TCP):
            protocol_type = 'tcp'
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol_type = 'udp'
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol_type = 'icmp'
            src_port = dst_port = 0
        else:
            protocol_type = 'other'
            src_port = dst_port = 0
        
        # Connection key
        conn_key = (src_ip, dst_ip, dst_port, protocol_type)
        
        # Analyze connection
        self.analyze_connection_state(packet, conn_key)
        conn = self.connections[conn_key]
        
        # Basic features
        duration = conn['duration']
        src_bytes = conn['src_bytes']
        dst_bytes = conn['dst_bytes']
        
        # Land attack
        land = 1 if src_ip == dst_ip else 0
        
        # Fragment and urgent
        wrong_fragment = conn['wrong_fragments']
        urgent = conn['urgent_packets']
        
        # Content features (heuristic-based)
        hot = 1 if dst_port in [80, 443, 21, 22, 23] and src_bytes > 1000 else 0
        num_failed_logins = conn['failed_logins']
        logged_in = 1 if conn['logged_in'] else 0
        num_compromised = conn['compromised_conditions']
        root_shell = 1 if conn['root_access'] else 0
        su_attempted = 1 if conn['login_attempts'] > 5 else 0
        num_root = 1 if root_shell else 0
        num_file_creations = min(conn['file_creations'], 10)
        num_shells = min(conn['shells_opened'], 5)
        num_access_files = min(conn['access_files'], 10)
        is_host_login = 1 if dst_port in [22, 23, 513, 514] else 0
        is_guest_login = 1 if num_failed_logins > 0 and logged_in == 0 else 0
        
        # Connection count features
        count, srv_count = self.calculate_connection_counts(conn_key, current_time)
        
        # Error rates
        serror_rate, srv_serror_rate, rerror_rate, srv_rerror_rate = \
            self.calculate_error_rates(conn_key, count, srv_count)
        
        # Service rates
        same_srv_rate = srv_count / max(count, 1)
        diff_srv_rate = 1.0 - same_srv_rate if same_srv_rate < 1.0 else 0.0
        
        # Service diversity rate (simplified)
        srv_diff_host_rate = min(len(conn['services']) * 0.1, 1.0)
        
        # Host-based features
        host_features = self.calculate_host_features(dst_ip, current_time)
        
        # Compile all features
        nsl_features = {
            'duration': float(duration),
            'src_bytes': int(src_bytes),
            'dst_bytes': int(dst_bytes),
            'land': int(land),
            'wrong_fragment': int(wrong_fragment),
            'urgent': int(urgent),
            'hot': int(hot),
            'num_failed_logins': int(num_failed_logins),
            'logged_in': int(logged_in),
            'num_compromised': int(num_compromised),
            'root_shell': int(root_shell),
            'su_attempted': int(su_attempted),
            'num_root': int(num_root),
            'num_file_creations': int(num_file_creations),
            'num_shells': int(num_shells),
            'num_access_files': int(num_access_files),
            'is_host_login': int(is_host_login),
            'is_guest_login': int(is_guest_login),
            'count': int(count),
            'srv_count': int(srv_count),
            'serror_rate': float(serror_rate),
            'srv_serror_rate': float(srv_serror_rate),
            'rerror_rate': float(rerror_rate),
            'srv_rerror_rate': float(srv_rerror_rate),
            'same_srv_rate': float(same_srv_rate),
            'diff_srv_rate': float(diff_srv_rate),
            'srv_diff_host_rate': float(srv_diff_host_rate),
            'dst_host_count': int(host_features['dst_host_count']),
            'dst_host_srv_count': int(host_features['dst_host_srv_count']),
            'dst_host_same_srv_rate': float(host_features['dst_host_same_srv_rate']),
            'dst_host_diff_srv_rate': float(host_features['dst_host_diff_srv_rate']),
            'dst_host_same_src_port_rate': float(host_features['dst_host_same_src_port_rate']),
            'dst_host_srv_diff_host_rate': float(host_features['dst_host_srv_diff_host_rate']),
            'dst_host_serror_rate': float(host_features['dst_host_serror_rate']),
            'dst_host_srv_serror_rate': float(host_features['dst_host_srv_serror_rate']),
            'dst_host_rerror_rate': float(host_features['dst_host_rerror_rate']),
            'dst_host_srv_rerror_rate': float(host_features['dst_host_srv_rerror_rate'])
        }
        
        return nsl_features
    
    def cleanup_old_connections(self, current_time):
        """Clean up old connection data to prevent memory issues"""
        cleanup_threshold = current_time - 300  # 5 minutes
        
        keys_to_remove = []
        for conn_key, conn in self.connections.items():
            if conn['last_update'] < cleanup_threshold:
                keys_to_remove.append(conn_key)
        
        for key in keys_to_remove:
            del self.connections[key]
        
        # Clean connection window
        for key in list(self.connection_window.keys()):
            self.connection_window[key] = [
                t for t in self.connection_window[key] 
                if t > cleanup_threshold
            ]