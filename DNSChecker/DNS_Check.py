#!/usr/bin/python3
import checkdmarc, argparse, json, shutil, os

Parser = argparse.ArgumentParser(description='To check DNS.')
Parser.add_argument('-d', '--domain')
Args = Parser.parse_args()

if Args.domain:
    print('[+] Retrieving details for domain: ' + Args.domain + '.')
    domains = [Args.domain]
    results = checkdmarc.check_domains(domains)

    print(results['base_domain'])
    output_dict = json.dumps(results, indent=4, sort_keys=True)
    json_dict = json.loads(output_dict)
    print(output_dict)

    NS_Hosts = json_dict['ns']['hostnames']
    MX_Hosts = json_dict['mx']['hosts']
    DMARC_Record = json_dict['dmarc']['record']a
    DMARC_Location = json_dict['dmarc']['location']
    DMARC_Valid = json_dict['dmarc']['valid']
    DNSSEC_Enabled = json_dict['dnssec']
    SPF_Record = json_dict['spf']['record']
    SPF_Valid = json_dict['spf']['valid']

    print('-' * shutil.get_terminal_size().columns)
    print("NS Information:")
    print('-' * shutil.get_terminal_size().columns)

    if NS_Hosts:
        print("[i] NS Hostnames: \n[i] " + "\n[i] ".join(NS_Hosts))

    else:
        print("[i] NS Hostnames: N/A")

    print('-' * shutil.get_terminal_size().columns)
    print("MX Information:")
    print('-' * shutil.get_terminal_size().columns)

    if MX_Hosts:
        i = 1

        for MX_Host in MX_Hosts:
            print("[i] Hostname: " + MX_Host['hostname'] + "\n[i] Matching IP Address: " + "\n[i] Matching IP Address: ".join(MX_Host['addresses']))

            if MX_Host['starttls']:
                print("[i] STARTTLS Enabled: " + str(MX_Host['starttls']))

            else:
                print("[i] STARTTLS Enabled: False")

            if MX_Host['tls']:
                print("[i] TLS Enabled: " + str(MX_Host['tls']))

            else:
                print("[i] TLS Enabled: False")

            if i < len(MX_Hosts):
                Modified_Length = shutil.get_terminal_size().columns - 3
                Modified_String = '-' * Modified_Length
                print('[i]' + Modified_String)
                i += 1

    else:
        print("[i] MX Hosts: N/A")

    print('-' * shutil.get_terminal_size().columns)
    print("DMARC Information:")
    print('-' * shutil.get_terminal_size().columns)

    if DMARC_Record:
        print("[i] DMARC Record: " + DMARC_Record)

    else:
        print("[i] DMARC Record: N/A")

    if DMARC_Location:
        print("[i] DMARC Location: " + DMARC_Location)

    else:
        print("[i] DMARC Location: N/A")

    if DMARC_Valid:
        print("[i] Is DMARC Valid: " + str(DMARC_Valid))

    else:
        print("[i] Is DMARC Valid: False")

    print('-' * shutil.get_terminal_size().columns)
    print("DNSSEC Information:")
    print('-' * shutil.get_terminal_size().columns)

    if DNSSEC_Enabled:
        print("[i] Is DNSSEC Enabled: " + str(DNSSEC_Enabled))

    else:
        print("[i] Is DNSSEC Enabled: False")

    print('-' * shutil.get_terminal_size().columns)
    print("SPF Information:")
    print('-' * shutil.get_terminal_size().columns)

    if SPF_Record:
        print("[i] SPF Record: " + SPF_Record)

    else:
        print("[i] SPF Record: N/A")

    if SPF_Valid:
        print("[i] Is SPF Valid: " + str(SPF_Valid))

    else:
        print("[i] Is SPF Valid: False")
