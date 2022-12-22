#!/usr/bin/env python3

# Title: NETWORK CRAWLER
# Author: Madhav Kumar
# Time: 19 December 2022 17:11 

# This is a Network Crawler Program, it crawls on a network provided the network address (Router's Ip or Default Gateway) and returns the active hosts
# version 2.0.0

# modules
import scapy.all as scapy 
import socket
import time,sys,os

# # logging
# import logging
# logging.getLogger('network-crawler-new.py')

# check if the script is executed as root user
import getpass
if getpass.getuser().lower()!="root":
    print("[!] Permission Denied")
    print(f"[!] try: sudo python3 {sys.argv[0]}")
    sys.exit()

class Crawler:
    def __init__(self,netaddr=''):
        self.NETWORK_ADDRESS = netaddr

    def scanNetwork(self):
        request = scapy.ARP(op='who-has',pdst=self.NETWORK_ADDRESS)
        broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
        response = scapy.srp(broadcast/request, timeout=1, verbose=True)
        self.alive_hosts = [[i.psrc,i.hwsrc.upper()] for i in response[0]]
        self.all_hosts = [[i.psrc,i.hwsrc.upper()] for i in response[1]]+self.alive_hosts
        return self.alive_hosts
    
    def ARP_spoof(self,targetip='',spoofip=''):
        pass


if __name__ == "__main__":
    os.system('clear')
    print("+====================================+")
    print("|        Network Crawler 2.0.0       |")
    print("+====================================+\n")
    gateway = input("[=] Enter the Network Address / broadcast / Default Gateway: ")
    time.sleep(1)
    print("[+] Default Gateway:",gateway)
    print("[+] Your hostname:",socket.gethostname())
    print("[+] Your IP:",socket.gethostbyname(socket.gethostname()),"\n")
    time.sleep(1)
    print("[*] Scanning the Network.....")
    crawler = Crawler(netaddr=gateway)
    crawler.scanNetwork()
    print("+====================================+")
    print("\tHOSTS FOUND\t\tMAC ADDRESS")
    for host in crawler.alive_hosts:
        print(f"\t{host[0]}\t\t{host[1]}")
    else:
        print("[-] No Online Host found")
        print("\tOther Hosts\t\tMAC Address")
        for host in crawler.all_hosts:
            print(f"\t{host[0]}\t\t{host[1]}")
    print()
