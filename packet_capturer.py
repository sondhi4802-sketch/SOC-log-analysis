import threading
import time
from datetime import datetime
from alerts.alert_manager import AlertManager
from scapy.all import sniff, IP, TCP, UDP, ICMP

class PacketCapturer:
    def __init__(self):
        self.packets = []
        self.packets_lock = threading.Lock()
        self.running = False
        self.thread = None
        self.alert_manager = AlertManager()
        self.total_captured = 0
        self.threat_count = 0
        self.total_bytes = 0
        self.error = None

        # Behavioral tracking structures
        self.ip_packet_times = {}     # ip -> list of packet timestamps (DoS)
        self.ip_accessed_ports = {}   # ip -> list of (port, timestamp) (Port Scan)
        self.ip_failed_logins = {}     # ip -> list of timestamps (Brute Force)
        self.dynamic_blacklist = {}    # ip -> threat reason (prevents further traffic)

    def start(self):
        if not self.running:
            self.running = True
            self.error = None
            self.thread = threading.Thread(target=self._capture_loop, daemon=True)
            self.thread.start()

    def stop(self):
        self.running = False

    def get_packets(self):
        with self.packets_lock:
            return list(self.packets)

    def get_metrics(self):
        return {
            "total_captured": self.total_captured,
            "threat_count": self.threat_count,
            "total_bytes": self.total_bytes,
            "running": self.running,
            "error": self.error
        }

    def clear(self):
        with self.packets_lock:
            self.packets.clear()
            self.total_captured = 0
            self.threat_count = 0
            self.total_bytes = 0
            self.ip_packet_times.clear()
            self.ip_accessed_ports.clear()
            self.ip_failed_logins.clear()
            self.dynamic_blacklist.clear()
            self.error = None

    def _capture_loop(self):
        def handle_scapy_packet(pkt):
            if not self.running:
                return
            
            try:
                if pkt.haslayer(IP):
                    ip_layer = pkt[IP]
                    src_ip = ip_layer.src
                    dest_ip = ip_layer.dst
                    length = len(pkt)
                    
                    # Protocol extraction
                    proto_name = "OTHER"
                    sport = 0
                    dport = 0
                    payload = ""
                    
                    if pkt.haslayer(TCP):
                        proto_name = "TCP"
                        sport = pkt[TCP].sport
                        dport = pkt[TCP].dport
                        payload = str(pkt[TCP].payload)
                    elif pkt.haslayer(UDP):
                        proto_name = "UDP"
                        sport = pkt[UDP].sport
                        dport = pkt[UDP].dport
                        payload = str(pkt[UDP].payload)
                    elif pkt.haslayer(ICMP):
                        proto_name = "ICMP"
                        payload = str(pkt[ICMP].payload)
                        
                    # Filter payloads
                    if payload.startswith("b'") or payload.startswith('b"'):
                        payload = payload[2:-1] # strip b'...'
                    
                    info = f"{proto_name} Traffic ({sport} -> {dport})"
                    if proto_name == "ICMP":
                        info = "ICMP Ping / Network Diagnostic"
                    elif proto_name == "TCP" and dport == 80:
                        info = "HTTP Web Traffic"
                    elif proto_name == "UDP" and (sport == 53 or dport == 53):
                        proto_name = "DNS"
                        info = "DNS Query / Response"

                    parsed_packet = {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                        "src": src_ip,
                        "dest": dest_ip,
                        "proto": proto_name,
                        "sport": sport,
                        "dport": dport,
                        "length": length,
                        "info": info,
                        "payload": payload[:150],
                        "threat": False,
                        "threat_type": "",
                        "severity": ""
                    }
                    
                    # Run threat analysis
                    self._detect_threats(parsed_packet)
                    
                    # Store packet
                    with self.packets_lock:
                        self.packets.insert(0, parsed_packet)
                        if len(self.packets) > 50:
                            self.packets.pop()
                            
                    self.total_captured += 1
                    self.total_bytes += length
            except Exception:
                pass

        def stop_filter(pkt):
            return not self.running

        try:
            # Sniff using Scapy (automatically targets Npcap loops and adapter lists)
            sniff(prn=handle_scapy_packet, stop_filter=stop_filter, store=0)
        except Exception as e:
            self.error = f"Sniffing Error: {str(e)}. (Ensure Npcap is installed in WinPcap-compatibility mode and you run as Administrator)"
            self.running = False

    def _detect_threats(self, packet):
        src = packet["src"]
        now = time.time()
        
        # 1. Rule: Block active blacklist targets
        if src in self.dynamic_blacklist:
            packet["threat"] = True
            packet["threat_type"] = f"{self.dynamic_blacklist[src]} Blocked"
            packet["severity"] = "High"
            packet["info"] = f"[BLOCK] Traffic blocked from source: {src} ({self.dynamic_blacklist[src]})"
            return

        # 2. Rule: DoS detection (Packets sent per 3 seconds)
        if src not in self.ip_packet_times:
            self.ip_packet_times[src] = []
        self.ip_packet_times[src] = [t for t in self.ip_packet_times[src] if now - t < 3.0]
        self.ip_packet_times[src].append(now)
        
        if len(self.ip_packet_times[src]) > 15:
            self.dynamic_blacklist[src] = "DoS Attacker"
            packet["threat"] = True
            packet["threat_type"] = "DoS Attack Blocked"
            packet["severity"] = "Critical"
            packet["info"] = f"[ALERT] DoS Attack: IP {src} sent {len(self.ip_packet_times[src])} packets in 3s"
            self.threat_count += 1
            self.alert_manager.save_alert(f"[CRITICAL] DoS Attack - Flood detected from IP {src}")
            return

        # 3. Rule: Port Scan detection (Unique ports scanned per 10 seconds)
        if src not in self.ip_accessed_ports:
            self.ip_accessed_ports[src] = []
        self.ip_accessed_ports[src] = [(p, t) for (p, t) in self.ip_accessed_ports[src] if now - t < 10.0]
        
        if packet["dport"] > 0:
            self.ip_accessed_ports[src].append((packet["dport"], now))
            
        unique_ports = set(p for (p, t) in self.ip_accessed_ports[src])
        if len(unique_ports) > 4:
            self.dynamic_blacklist[src] = "Port Scan Attacker"
            packet["threat"] = True
            packet["threat_type"] = "Port Scan Blocked"
            packet["severity"] = "Critical"
            packet["info"] = f"[ALERT] Port Scan: IP {src} scanned {len(unique_ports)} different ports in 10s"
            self.threat_count += 1
            self.alert_manager.save_alert(f"[CRITICAL] Port Scan - Multi-port scan detected from IP {src}")
            return

        # 4. Rule: Brute Force detection (Failed logins per 15 seconds)
        is_failed_login = "FAILED LOGIN" in packet["info"].upper() or "FAILED LOGIN" in packet["payload"].upper()
        if is_failed_login:
            if src not in self.ip_failed_logins:
                self.ip_failed_logins[src] = []
            self.ip_failed_logins[src] = [t for t in self.ip_failed_logins[src] if now - t < 15.0]
            self.ip_failed_logins[src].append(now)
            
            if len(self.ip_failed_logins[src]) > 3:
                self.dynamic_blacklist[src] = "Brute Force Attacker"
                packet["threat"] = True
                packet["threat_type"] = "Brute Force Blocked"
                packet["severity"] = "Critical"
                packet["info"] = f"[ALERT] Brute Force: IP {src} made {len(self.ip_failed_logins[src])} failed logins in 15s"
                self.threat_count += 1
                self.alert_manager.save_alert(f"[CRITICAL] Brute Force - Repeated authentication failures from IP {src}")
                return