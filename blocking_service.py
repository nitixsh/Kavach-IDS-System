import sqlite3
import subprocess
import platform
import time
import threading

def get_db_connection():
    conn = sqlite3.connect('ids_database.db')
    conn.row_factory = sqlite3.Row
    return conn

def block_ip_firewall(ip_address):
    """Block IP at firewall level"""
    try:
        system = platform.system()
        
        if system == "Windows":
            # Windows Firewall rule
            cmd = f'netsh advfirewall firewall add rule name="IDS_Block_{ip_address}" dir=in action=block remoteip={ip_address}'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ Blocked {ip_address} on Windows Firewall")
                return True
        elif system == "Linux":
            # iptables rule
            cmd = f'sudo iptables -A INPUT -s {ip_address} -j DROP'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ Blocked {ip_address} with iptables")
                return True
        
        return False
    except Exception as e:
        print(f"❌ Firewall blocking error for {ip_address}: {e}")
        return False

def unblock_ip_firewall(ip_address):
    """Unblock IP at firewall level"""
    try:
        system = platform.system()
        
        if system == "Windows":
            cmd = f'netsh advfirewall firewall delete rule name="IDS_Block_{ip_address}"'
            subprocess.run(cmd, shell=True, check=True)
        elif system == "Linux":
            cmd = f'sudo iptables -D INPUT -s {ip_address} -j DROP'
            subprocess.run(cmd, shell=True, check=True)
        
        print(f"✅ Unblocked {ip_address}")
        return True
    except Exception as e:
        print(f"❌ Firewall unblocking error for {ip_address}: {e}")
        return False


def blocking_service_loop():
    """Continuously monitor and apply firewall blocks"""
    print("🛡️ IP Blocking Service Started")
    blocked_ips_cache = set()
    
    while True:
        try:
            conn = get_db_connection()
            
            # Get IPs that should be blocked
            pending_blocks = conn.execute("""
                SELECT ip_address, attack_type FROM blocked_ips 
                WHERE is_blocked = 1
            """).fetchall()
            
            current_blocked_ips = set()
            for row in pending_blocks:
                ip = row['ip_address']
                current_blocked_ips.add(ip)
                
                # Apply firewall rule if not in cache
                if ip not in blocked_ips_cache:
                    if block_ip_firewall(ip):
                        blocked_ips_cache.add(ip)
            
            # Get IPs that should be unblocked
            unblocked = conn.execute("""
                SELECT ip_address FROM blocked_ips 
                WHERE is_blocked = 0 AND unblocked_at IS NOT NULL
            """).fetchall()
            
            for row in unblocked:
                ip = row['ip_address']
                if ip in blocked_ips_cache:
                    if unblock_ip_firewall(ip):
                        blocked_ips_cache.remove(ip)
                        # Clean up - can delete old unblock records
                        conn.execute("""
                            DELETE FROM blocked_ips 
                            WHERE ip_address = ? AND is_blocked = 0
                        """, (ip,))
                        conn.commit()
            
            conn.close()
            time.sleep(3)  # Check every 3 seconds
            
        except Exception as e:
            print(f"Blocking service error: {e}")
            time.sleep(10)
            
if __name__ == "__main__":
    blocking_service_loop()