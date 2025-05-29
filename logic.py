import socket
import time
from scapy.all import AsyncSniffer, IP, TCP, UDP, ARP, ICMP, DNS, BOOTP, DHCP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.tls.all import TLSClientHello, TLS_Ext_ServerName
try:
    from scapy.layers.inet import IGMP
except ImportError:
    IGMP = None

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

local_ip = get_local_ip()

# Глобальные переменные
packets = []
http_events = []
dns_queries = []
dns_errors = []
arp_alerts = []
arp_cache = {}
stats = {'incoming': 0, 'outgoing': 0, 'alert': 0}
current_bpf = ''
sniffer = None
start_time = None

def set_start_time():
    global start_time
    start_time = time.time()

def packet_callback(pkt):
    global start_time
    if start_time is None or IP not in pkt:
        return

    if pkt.haslayer(ARP) and pkt[ARP].op == 2:
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        old = arp_cache.get(ip)
        if old and old != mac:
            alert = {
                'time': round(time.time() - start_time, 3),
                'ip': ip, 'old_mac': old, 'new_mac': mac
            }
            arp_alerts.append(alert)
            stats['alert'] += 1
        arp_cache[ip] = mac

    ts = pkt.time - start_time
    t = f"{ts:.6f}"
    alert = False

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    is_in = dst_ip == local_ip
    is_out = src_ip == local_ip
    direction = 'incoming' if is_in else 'outgoing'
    stats[direction] += 1

    if pkt.haslayer(HTTPRequest):
        http = pkt[HTTPRequest]
        info = f"{http.Method.decode(errors='ignore')} http://{http.Host.decode(errors='ignore')}{http.Path.decode(errors='ignore')}"
        http_events.append({'time': t, 'src': src_ip, 'dst': dst_ip, 'type': 'HTTP Request', 'info': info})
    elif pkt.haslayer(HTTPResponse):
        resp = pkt[HTTPResponse]
        info = f"HTTP/{resp.Http_Version.decode(errors='ignore')} {resp.Status_Code.decode(errors='ignore')}"
        http_events.append({'time': t, 'src': src_ip, 'dst': dst_ip, 'type': 'HTTP Response', 'info': info})
    elif pkt.haslayer(TLSClientHello):
        for ext in getattr(pkt[TLSClientHello], 'extensions', []) or []:
            if isinstance(ext, TLS_Ext_ServerName):
                sni = ext.servernames[0].servername.decode(errors='ignore')
                http_events.append({'time': t, 'src': src_ip, 'dst': dst_ip, 'type': 'HTTPS SNI', 'info': f"SNI: {sni}"})
                break

    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        if dns.qr == 0 and getattr(dns, 'qd', None):
            name = dns.qd.qname.decode(errors='ignore').rstrip('.')
            dns_queries.append(name)
        elif dns.qr == 1 and getattr(dns, 'qd', None) and getattr(dns, 'rcode', 0) != 0:
            name = dns.qd.qname.decode(errors='ignore').rstrip('.')
            dns_errors.append(name)

    proto, sport, dport = '', None, None
    if pkt.haslayer(TCP):
        proto = 'TCP'
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        flags, seq, ack = pkt[TCP].flags, pkt[TCP].seq, pkt[TCP].ack
        info = f"{sport}->{dport} [{flags}] Seq={seq} Ack={ack}"
        #if flags & 0x02 and flags & 0x01: alert = True
        #if (flags & 0x04) and (flags & 0x10): alert = True
    elif pkt.haslayer(UDP):
        proto = 'UDP'
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
        info = f"{sport}->{dport} Len={len(pkt[UDP].payload)}"
    elif IGMP and pkt.haslayer(IGMP):
        proto = 'IGMP'; info = f"type={pkt[IGMP].type}"
    elif pkt.haslayer(ARP):
        proto = 'ARP'; info = f"op={pkt[ARP].op}"
    elif pkt.haslayer(ICMP):
        proto = 'ICMP'; info = f"type={pkt[ICMP].type}"
    elif pkt.haslayer(BOOTP) or pkt.haslayer(DHCP):
        proto = 'DHCP'; info = 'DHCP packet'
    else:
        proto = pkt.lastlayer().name
        info = ''

    if alert: stats['alert'] += 1
    src = f"{src_ip}:{sport}" if sport else src_ip
    dst = f"{dst_ip}:{dport}" if dport else dst_ip
    length = len(pkt)

    packets.append({
        'time': t, 'src': src, 'dst': dst,
        'proto': proto, 'len': length, 'info': info,
        'direction': direction, 'alert': alert
    })
    if len(packets) > 100: packets.pop(0)
    if len(http_events) > 100: http_events.pop(0)

def start_sniffer():
    global sniffer
    sniffer = AsyncSniffer(prn=packet_callback, store=False, filter=current_bpf or None)
    sniffer.start()
