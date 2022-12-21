#!/usr/bin/env python3

# Author: Madhav Kumar
# Time: 19 December 2022 17:11 

# This is a Network Crawler Program, it crawls on a network provided the network address (Router's Ip or Default Gateway) and returns the active hosts
# version 2.0.0

# modules
import scapy.all as scapy 
import time 



"""
NOTE: SUBNET MASKING TO BE REDONE

Below table will show the masks that can be drawn on with Class C networks.

Subnet Mask - Last octet binary Value - No. of hosts connected
255.255.255.128 - 10000000 -  126
255.255.255.192 - 11000000 - 62  
255.255.255.224 - 11100000 - 30 
255.255.255.240 - 11110000 - 14 
255.255.255.248 - 11111000 - 6
255.255.255.252 - 11111100 - 2   


"""

class Scan:
    def __init__(self, ip):
        self.ipaddr = ip 

    def connect(self):
        s = socket.socket()

        

        # status of connected with the ip provided
        # 1 ==> Host is Up 
        # 0 ==> Host is Down
        # -1 ==> Host is Denying the Connection (Probably the Firewall)
        self.status = 0
        self.MACaddress = ""

class Crawler:
    def __init__(self):
        pass

    def setNetwork(self,netaddr):
        self.NETWORK_ADDRESS = netaddr

    def getMAC(self,ip):
        request = scapy.ARP(op='who-has',pdst=ip)
        broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        packet =  broadcast/request
        resp, _ = srp(packet, timeout = 2, retry = 10, verbose = False)
        
        

class Crawler:
    def __init__(self,file=''):
        if len(file)==0: self.all_hosts = []
        else: 
            with open(file,'r') as f: self.all_hosts = f.read().split()
        self.ARPtable = []

    def debug(self,exit=True,*args,**kwargs):
        print(*args)
        print(f"[-] Default Gateway: {self.DEFAULT_GATEWAY}")
        print(f"[-] Subnet Mask: {self.SUBNET_MASK}")
        print(f"[-] Network Address: {self.NETWORK_ADDRESS}")
        for i in kwargs: print(f"[-] {i}: {kwargs[i]}")
        if exit: exit()
        
        
    def setNetwork(self, Default_Gateway='', Subnet_Mask='255.255.255.0'):
        self.DEFAULT_GATEWAY = Default_Gateway
        self.SUBNET_MASK = Subnet_Mask
        if len(self.DEFAULT_GATEWAY) == 0: self.debug("[!] Provide the Router's IP (Default Gateway)")
        if self.SUBNET_MASK not in ['255.255.0.0','255.255.0.0']: self.debug("[!] Invalid Subnet Mask")
        print("[+] Network Address: {}".format(self.DEFAULT_GATEWAY))
        print("[+] Subnet Mask: {}".format(self.SUBNET_MASK))

        # targets
        i = self.SUBNET_MASK.split('.').index('0')
        self.NETWORK_ADDRESS = "".join(self.DEFAULT_GATEWAY.split('.')[0:i])
        if i==3: self.all_hosts = [f'{self.NETWORK_ADDRESS}.{h}' for h in range(256)]
        elif i==2: self.all_hosts = [f'{self.NETWORK_ADDRESS}.{n}.{h}' for n in range(256) for h in range(256)]
        else: self.debug("[!] Something went wrong") 

    def scanNetwork(self):
        # check if connected to the Network
        conn = Scan(self.DEFAULT_GATEWAY).status
        if conn==1:
            print("[+] Connection to the Private Network CHECK")
            print("[+] Scanning for acitve hosts on the Network...")
            for host in self.all_hosts:
                conn = Scan(host)
                if conn.status==1:
                    print(f'[1] {host} is Up')
                    self.ARPtable[host] = conn.MACaddress
                elif conn.status==0: print(f"[0] {host} not found")
                else: print(f"[-1] {host} is not allowing pings") 
        elif conn==0: print("[-] Not Connected to the Network")
        else: print("[!] Unable to Connect")
    
    def printResults(self):
        print("[+] Successfully Scanned the Network")
        print("[=] Your IP: {}".format(socket.gethostbyname(socket.gethostname())))
        PRINT(" ## IP address ##    ## MAC Address ##")
        for host in self.ARPtable:
            print(f"[+]  {host} {self.ARPtable[host]}")
        
        



if __name__ == "__main__":
    crawler = Crawler()
    




"""
# NOTE: For MAC Address

from scapy.all import *
import sys
from colorama import Fore, Back, Style

def getmac(host_ip, host_count):

    # If not sudo, don't allow to continue
    if not 'SUDO_UID' in os.environ.keys():
        print(f'[{Fore.RED}!{Style.RESET_ALL}] Permission error: {Fore.RED}You need root privileges for this feature.{Style.RESET_ALL}')
        sys.exit()

    try:
        
        if host_count > 0:
            print(f'\n[{Fore.YELLOW}?{Style.RESET_ALL}] Trying to get MAC address of {Fore.YELLOW}{host_ip}{Style.RESET_ALL}...')
        else:
            print(f'[{Fore.YELLOW}?{Style.RESET_ALL}] Trying to get MAC address of {Fore.YELLOW}{host_ip}{Style.RESET_ALL}...')
        
        packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op='who-has', pdst = host_ip)
        resp, _ = srp(packet, timeout = 2, retry = 10, verbose = False)

        if resp:
            for _, r in resp:
                print(f'[{Fore.GREEN}+{Style.RESET_ALL}] MAC address of {Fore.YELLOW}{host_ip}{Style.RESET_ALL}: {Fore.GREEN}{r[Ether].src.upper()}{Style.RESET_ALL}')
        else:
                print(f'[{Fore.RED}!{Style.RESET_ALL}] {Fore.RED}No MAC address for{Style.RESET_ALL} {Fore.YELLOW}{host_ip}{Style.RESET_ALL} {Fore.RED}was found.{Style.RESET_ALL}')

    except Exception as e:
        print(f'[{Fore.RED}!{Style.RESET_ALL}] Error: {Fore.RED}{e}{Style.RESET_ALL}')

    except KeyboardInterrupt:
        sys.exit('^C\n')








"""
