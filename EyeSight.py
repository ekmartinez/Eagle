import requests
from scapy.all import *
from ipaddress import IPv4Interface

def arp_sweep(target, mask):
    print("\nARP Method\n----------")
    timeout = 2
    broadcast = "ff:ff:ff:ff:ff:ff"
    subnet = str(IPv4Interface(f"{target}/{mask}").network) # returns subnet mask 
    ans, unans = srp(Ether(dst=broadcast)/ARP(pdst=subnet), timeout=timeout)
    input("\nCompleted, press enter to continue.")
    return ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc% is up"))

def icmp_sweep(target, mask): 
    print("\nICMP Method\n-----------")
    timeout = 3
    subnet = str(IPv4Interface(f"{target}/{mask}").network) # returns subnet mask 
    ans, unans = sr(IP(dst=subnet)/ICMP(), timeout=timeout)
    input("\nCompleted, press enter to continue.")
    return ans.summary(lambda s,r: r.srpintf("%IP.src% is up"))

def syn_scan(target, prange): 
    ans, unans = sr(IP(dst=target)/TCP(sport=RandShort(),dport=prange, flags="S"))
    input("\nCompleted, press enter to continue.")
    return ans.summary(lfilter = lambda s,r: r.sprintf("%TCP.flags%") == "SA", prn=lambda s,r: r.sprintf("%TCP.sport% is open"))

def ack_scan(target, prange):
    ans, unans = sr(IP(dst=target)/TCP(dport=prange, flags="A"))
    for s, r in ans:
        if s[TCP].dport == r[TCP].sport:
            print("%d is unfiltered" % s[TCP].dport)
    
    input("\nCompleted, press enter to continue.")

    return True

def xmas_scan(target, prange):
    ans, unans = sr(IP(dst=target)/TCP(dport=prange, flags="FPU"))
    return ans.summary(lfilter = lambda s,r: r.sprintf("%TCP.flags%") != "RST", prn=lambda s,r: r.sprintf("%TCP.sport% is open"))

def trace():
    ans, unans = sr(IP(dst=target, ttl=(4,25),id=RandShort())/TCP(flags=0x2))
    for snd, rcv in ans:
        print(snd.ttl, rcv.src, isinstance(rcv.payload, TCP))

    return True

def FindDirs(wlist, port=443, ssl=True):
    pass        

def FindSubs(self, wlist, port=443, ssl=True):
    pass












