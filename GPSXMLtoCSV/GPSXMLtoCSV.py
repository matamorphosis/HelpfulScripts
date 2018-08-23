#!/usr/bin/env python

import argparse, sys

parser = argparse.ArgumentParser(description="This tool converts .gpsxml files which are outputted from kismet, to a .csv file, usable with Splunk.")
parser.add_argument('-i', '--input', help='This option is required to specify the location of the .gpsxml file to import')
args = parser.parse_args()

if not args.input:
	sys.exit("[-] No input file provided.")

try:
	f1 = open(args.input, 'r')

except:
	sys.exit("[-] Unable to open input file provided.")
	
lines = f1.readlines()
f1.close()

f2 = open('output.csv', 'w')
f2.write("DEST_MAC SOURCE_MAC TIME_SEC TIME_USEC LAT LON SPEED HEADING FIX SIGNAL_DBM NOISE_DBM")

lines = filter(lambda x: not x.isspace(), lines)

for line in lines:
	if not any (value in line for value in("GP:SD:TR:AC:KL:OG", "<network-file>", "<gps-run", "<!DOCTYPE", "<?xml version", "00:00:00:00:00:00", "</gps-run>")):
		line = line.rstrip('\n\r')
		f2.write("\n" + line.replace('"', '').replace('time-sec=', '').replace('time-usec=', '').replace('lat=', '').replace('lon=', '').replace('spd=', '').replace('heading=', '').replace('fix=', '').replace('signal_dbm=', '').replace('noise_dbm=', '').replace('<gps-point bssid=', '').replace('source=', '').replace('/>', '').replace('    ', ''))

f2.close()
