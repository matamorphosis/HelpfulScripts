#!/usr/bin/python3
# Calculate Session Identifier entropy with Claude Shannon formula.
import math, sys, time, urllib.request, argparse

Parser = argparse.ArgumentParser(description="""Session entropy calculator.""", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
Parser.add_argument('-u', '--url', help='URL of target site.', required=True, type=str)
Parser.add_argument('-c', '--cookie', help='Name of the cookie to target.', required=True, type=str)
Arguments = Parser.parse_args()

Target_URL = Arguments.url
Target_Cookie = Arguments.cookie

# Initialize
charlist = []
maxlength = 0

def addcharlist(cl, v):
    ncl = list(set(cl + list(v)))
    return ncl

# SessionID collection
print ("[i] Collecting " + Target_Cookie + "...")

for i in range(0, 10000):
    time.sleep(0.1)
    Headers = {"User-Agent": "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)"}
    Request = urllib.request.Request(Target_URL, None, Headers)
    Response = urllib.request.urlopen(Request)
    
    for h, v in Response.headers.items():

        if h.lower() == "set-cookie":
            r = v.split(';')[0].strip()
            n = r.find('=')

            if Target_Cookie == r[:n]:
                charlist = addcharlist(charlist, r[n+1:])

                if len(r[n+1:]) > maxlength:
                    maxlength = len(r[n+1:])

                break

print ("[+] Collected.")

# Calculation
fb = len(charlist)
fl = maxlength
fbl = math.pow(fb, fl)
fH = math.log2(fbl)

# Report
print ("    Length   : " + str(fl))
print ("    Charlist : " + str(fb))
print ("    Strength : " + str(fH) + " bit(s).")
print ("[+] Ok.")
exit()
