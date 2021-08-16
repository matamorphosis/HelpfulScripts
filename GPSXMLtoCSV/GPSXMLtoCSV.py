#!/usr/bin/env python3
import argparse, sys

parser = argparse.ArgumentParser(description="This tool converts .gpsxml files which are outputted from kismet, to a .csv file, usable with Splunk.")
parser.add_argument('-i', '--input', required=True, help='This option is required to specify the location of the .gpsxml file to import')
args = parser.parse_args()

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

		for item_to_remove in ["\"", "time-sec=", "time-usec=", "lat=", "lon=", "spd=", "heading=", "fix=", "signal_dbm=", "noise_dbm=", "<gps-point bssid=", "source=", "/>", "    "]:
			line = line.replace(item_to_remove, "")
		
		f2.write("\n" + line)

f2.close()