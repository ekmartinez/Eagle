import sys
import requests
import subprocess
from scapy.all import *

""" 
PENDING ISSUES:

LIVE HOST IDENTIFICATION: For now lets ask for subnet, then we'll 
see if we can calculate subnet from given target. 

PORT SCANNER: For now lets ask for port range, then we'll
see if we can allow single, multiple or all ports.

HTTP ENUMERATION: Write Brute-Force Scanners.
""" 

class Eagle:
    def __init__(self, target):
        self.target = target
    
    def arp_sweep(self, subnet):
        timeout = 2
        broadcast = "ff:ff:ff:ff:ff:ff"
        print("\nARP Method\n----------")
        ans, unans = srp(Ether(dst=broadcast)/ARP(pdst=subnet), timeout=timeout)
        print(ans.summary(lambda s,r: r.sprintf("%Ether.src% %ARP.psrc% is up")))
        input("\nCompleted, press enter to continue.")
        return True

    def icmp_sweep(self, subnet): 
        print("\nICMP Method\n-----------")
        timeout = 3
        ans, unans = sr(IP(dst=subnet)/ICMP(), timeout=timeout)
        print(ans.summary(lambda s,r: r.srpintf("%IP.src% is up")))
        input("\nCompleted, press enter to continue.")
        return True

    def syn_scan(self, prange): 
        ans, unans = sr(IP(dst=self.target)/TCP(sport=RandShort(),dport=prange, flags="S"))
        print(ans.summary(lfilter = lambda s,r: r.sprintf("%TCP.flags%") == "SA", prn=lambda s,r: r.sprintf("%TCP.sport% is open")))
        input("\nCompleted, press enter to continue.")
        return True

    def ack_scan(self, prange):
        ans, unans = sr(IP(dst=self.target)/TCP(dport=prange, flags="A"))
        for s, r in ans:
            if s[TCP].dport == r[TCP].sport:
                print("%d is unfiltered" % s[TCP].dport)
        
        input("\nCompleted, press enter to continue.")

        return True

    def xmas_scan(self, prange):
        ans, unans = sr(IP(dst=self.target)/TCP(dport=prange, flags="FPU"))
        print(ans.summary(lfilter = lambda s,r: r.sprintf("%TCP.flags%") != "RST", prn=lambda s,r: r.sprintf("%TCP.sport% is open")))
        return True

    def trace(self):
        ans, unans = sr(IP(dst=target, ttl=(4,25),id=RandShort())/TCP(flags=0x2))
        for snd, rcv in ans:
            print(snd.ttl, rcv.src, isinstance(rcv.payload, TCP))

        return True

    def dir_enum(self, wlist, port=443, ssl=True):
        pass        

    def subdomain_enum(self, wlist, port=443):
        pass

    def banner(self):
        print('\n' + '-'*65 + '\n')
        print(('*'*20) + '  `````\__Eagle__/`````  ' + ('*'*20))
        print('\n' + '-'*65 + '\n')

    def set_target(self):
        new_target = input("Enter new target: ")
        self.target = new_target
    
    def live_hosts(self):
        while(True):
            method = input("""

        Scanning Methods:
            
            (1)  -  ARP Method
            (2)  -  ICMP Method
            (3)  -  Exit

            Choose an option >>> """)
            
            subnet = input("\nEnter subnet address in CIDR Notation (0.0.0.0/24) >>> ")
            
            match method:
                case "1":
                    self.arp_sweep(subnet)
                case "2":
                    self.icmp_sweep(subnet)
                case "3":
                    break
                case _:
                    print("You have entered an invalid option")

    def port_scan(self):
            while(True):
                method = input("""

            Scanning Methods:
                
                (1)  -  SYN Method
                (2)  -  ACK Method 
                (3)  -  Xmas Method
                (4)  -  Exit

                Options for {self.target} >>> """)
                
                port_range = input("\nEnter port range (Ex: 1-1024) >>> ")
                
                match method:
                    case "1":
                        self.syn_scan(port_range)
                    case "2":
                        self.ack_scan(port_range)
                    case "3":
                        self.xmas_scan(port_range)
                    case "4":
                        break
                    case _:
                        print("You have entered an invalid option")

    def http_dir_enum(self):
        while(True):
            method = input(f"""

        Brute-Force Methods:
            
            (1)  -  Directory
            (2)  -  Subdomain
            (3)  -  Exit

            Options for {self.target} >>> """)
            
            wordlist = input("\nEnter wordist's path (Ex: /home/dir/wordlist.txt) >>> ")
            port = input("Enter port (default is 443) >>> ")
            ssh = input("Enable SSL (Default yes) (y/n) >>> ") 
            
            match method:
                case "1":
                    self.dir_enum(wordlist)
                case "2":
                    self.subdomain_enum(wordlist)
                case "3":
                    break
                case _:
                    print("You have entered an invalid option")
   
    def fly(self):
        while(True):
            subprocess.run("clear")
            self.banner()
            option = input(f'''

        Options for {self.target}:

            (1)  -  Live Hosts
            (2)  -  Port Scan
            (3)  -  Traceroute
            (4)  -  Directory Enum
            (5)  -  Enter New Target
            (6)  -  Exit

        Choose an option >>> ''')    
            
            match option:
                case "1":
                    self.live_hosts()
                case "2":
                    self.port_scan()
                case "3":
                    self.trace()
                case "4":
                    self.http_dir_enum()
                case "5":
                    self.set_target()
                case "6":
                    sys.exit()
                case _:
                    print("You have entered an invalid option")
                    input()

def target():
    subprocess.run("clear")
    target = input("\n`````\__Eagle__/`````: To begin provide an IP for recon >>> ")
    return target

if __name__ == '__main__':
    eagle = Eagle(target())
    #eagle.fly()
    print("SXQgaXMgbm90IHJlYWR5IHlldC4=")
