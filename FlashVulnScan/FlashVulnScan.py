#!/usr/bin/env python

import sys, os, re, argparse

unsafemethods = ["loadVariables","loadMovie","getURL","NavigateToURL","loadMovieNum","FScrollPane.loadScrollContent","LoadVars.load","LoadVars.send","XML.load","Sound.loadSound","NetStream.play","flash.external.ExternalInterface.call","htmlText"]

parser = argparse.ArgumentParser(description='FlashVulnScan is a tool that checks for possible vulnerable variables and methods in a decompiled .swf application.')
parser.add_argument('-d', '--decompile', help='This option is used to specify a .swf file that needs to be decompiled before scanning can commence. ./FlashVulnScan.py -d file.swf')
parser.add_argument('-l', '--location', help='This option will specify the output folder of the decompiled files when used in accordance with the -d option. Otherwise this option specifies the location of pre-decompiled files when used alone. ./FlashVulnScan.py -d file.swf -l /root/Downloads/folder-to-decompile-to/')
args = parser.parse_args()

if args.decompile:
	swffile = args.decompile
	swffileregex = re.search(r".*\.swf", swffile)
	
	if not swffileregex:
		sys.exit("[-] Please provide a valid flash (.swf) application")
		
	else:
		if args.location:
			destfolder = args.location
			
		else:
			destfolder = "/"
			
		print("[+] Decompiling " + swffile + " and exporting scripts to the " + destfolder + " directory. Please be patient.")
		os.system("ffdec -export script " + destfolder + " " + swffile)
		print("[+] Finished exporting scripts.")
		
		try:
			os.chdir(destfolder)
		except:
			sys.exit("[-] Failed to change to directory " + destfolder + ".")

elif not args.decompile:
	if args.location:
		destfolder = args.location
		try:
			os.chdir(destfolder)
		except:
			sys.exit("[-] Failed to change to directory " + destfolder + ".")

print("[+] Searching for username and password locations in the source code.")
os.system("grep -n -r username * > UsernameLocations.txt")
os.system("grep -n -r password * > PasswordLocations.txt")
print("[+] Done. Review the output files for hardcoded credentials.")

print("[+] Searching for _root,_global, and _level0 variable locations in the source code.")	
os.system("grep -n -r _root * > _rootLocations.txt")
os.system("grep -n -r _global * > _globalLocations.txt")
os.system("grep -n -r _level0 * > _level0Locations.txt")
print("[+] Done. Review the output files for any risky variables.")

print("[+] Searching for IP addresses.")
os.system("grep -n -r -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' * > IPAddressLocations.txt")
print("[+] Done. Review the output file for IP addresses.")

outfile = "UnsafeMethods.txt"
infile = open(outfile,"w+")
infile.close()

print("[+] Searching for any unsafe methods in the source code.")
for method in unsafemethods:
	try:
		os.system("echo " + method + ": >> " + outfile)
		os.system("grep -n -r " + method + " * >> " + outfile)
	except:
		print("[-] Failed to find methods.")
print("[+] Done. Review the output files.")
