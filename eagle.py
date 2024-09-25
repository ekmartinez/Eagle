import sys
import EyeSight
import subprocess

class Eagle:
    def __init__(self, target):
        self.target = target

    def banner(self):
        print("\n" + "-"*50)
        print(("*"*15) + " `````\Eagle/`````  " + ("*"*15))
        print(("-"*50) + "\n")
          
    def live_hosts(self):
        while(True):
            method = input(f"""

        Scanning Options for {self.target}:
            
            (1)  -  ARP Method
            (2)  -  ICMP Method
            (3)  -  Exit

                Choose an option >>> """)
            
            match method:
                case "1":
                    mask = input("\nEnter subnet prefix  >>> ")
                    EyeSight.arp_sweep(self.target, mask)
                case "2":
                    mask = input("\nEnter subnet prefix  >>> ")
                    EyeSight.icmp_sweep(self.target, mask)
                case "3":
                    break
                case _:
                    print("You have entered an invalid option")

    def port_scan(self):
        while(True):
            method = input(f"""

        Scanning Options for {self.target} :
            
            (1)  -  SYN Method
            (2)  -  ACK Method 
            (3)  -  Xmas Method
            (4)  -  Exit

                Options for {self.target} >>> """)
            
            match method:
                case "1":
                    port_range = input("\nEnter port range (Ex: 1-1024) >>> ")
                    EyeSight.syn_scan(self.target, port_range)
                case "2":
                    port_range = input("\nEnter port range (Ex: 1-1024) >>> ")
                    EyeSight.ack_scan(self.target, port_range)
                case "3":
                    port_range = input("\nEnter port range (Ex: 1-1024) >>> ")
                    EyeSight.xmas_scan(self.target, port_range)
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
                    EyeSight.FindDirs(wordlist)
                case "2":
                    EyeSight.FindSubs(wordlist)
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

def target():
    target = input("\n`````\__Eagle__/`````: Enter a target >>> ")
    return target

if __name__ == "__main__":
    eagle = Eagle(target())
    eagle.fly()
    # print("SXQgaXMgbm90IHJlYWR5IHlldC4=")

""" 
PENDING ISSUES:

PORT SCANNER: For now lets ask for port range, then we'll
see if we can allow single, multiple or all ports.

HTTP ENUMERATION: Write Brute-Force Scanners.
""" 


