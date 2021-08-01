#!/usr/bin/python3
import base64, re, sys, urllib, argparse

def Read_File(File_Name):

    try:
    
        with open(File_Name) as File:
            File_Contents = File.read()
            File.close()

        return File_Contents

    except Exception as e:
        sys.exit(f'[-] {str(e)}')

def IdentifyandDecodeString(item, iteration):
    global string_type
    URL_Regex = re.search(r"\%[0-9a-fA-F]{2}", item)
    HTML_Regex = re.search(r"&#x[0-9a-fA-F]{2};", item)
    B64_Regex = re.search(r"^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$", item)
    Octal_Regex = re.search(r"([0-7]{3}\s?)+", item)
    Decimal_Regex = re.search(r"(\d{2,3}\s?)+", item)
    Binary_Regex = re.search(r"(\d{8}\s?)+", item)

    if B64_Regex:

        if iteration == 1 or string_type != "Base64":
            print("[i] Base64 Encoding Identified.")
            string_type = "Base64"

        try:
            return [True, base64.b64decode(item.encode()).decode()]

        except:
            return [False, item]

    elif URL_Regex:

        if iteration == 1 or string_type != "URL":
            print("[i] URL Encoding Identified.")
            string_type = "URL"

        URL_Item = item.replace("%", "")

        try:
            return [True, bytearray.fromhex(URL_Item).decode()]

        except:
            return [False, item]

    elif HTML_Regex:

        if iteration == 1 or string_type != "HTML":
            print("[i] HTML Encoding Identified.")
            string_type = "HTML"

        URL_Item = item.replace("&#x", "")
        URL_Item = URL_Item.replace(";", "")

        try:
            return [True, bytearray.fromhex(URL_Item).decode()]

        except:
            return [False, item]
            
    elif Decimal_Regex:
    
        if iteration == 1 or string_type != "Decimal":
            print("[i] Decimal Encoding Identified.")
            string_type = "Decimal"
            
        Dec_Chars = item.split()
        Filtered_Chars = []
        
        try:
        
            for D_Char in Dec_Chars:
                Filtered_Chars.append(chr(D_Char))
                
            return [True, "".join(Filtered_Chars)]
        
        except:
            return [False, item]

    elif Binary_Regex:
    
        if iteration == 1 or string_type != "Binary":
            print("[i] Binary Encoding Identified.")
            string_type = "Binary"
            
        Dec_Chars = item.split(" ")
        Binary_Values = item.split()
        ASCII_String = ""
        
        try:
        
            for Binary_Value in Binary_Values:
                An_Integer = int(Binary_Value, 2)
                ASCII_Character = chr(An_Integer)
                ASCII_String += ASCII_Character
                
            return [True, ASCII_String]
        
        except:
            return [False, item]

    elif not any(char in ["~", "", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "`", "_", "+", "-", "=", "[", "]", "{", "}", "|", ";", ":", "'", "\"", ",", ".", "/", "<", ">", "?"] for char in item):
        Pure_Hex_Regex = re.search(r"[^%!@#$^&*()~`\[\]{}\\|;:\"\',./?><=\-+_G-Zg-z]{2}", item)

        if Pure_Hex_Regex:

            if iteration == 1 or string_type != "Hex":
                print("[i] Pure Hex Encoding Identified.")
                string_type = "Hex"

            try:
                return [True, bytearray.fromhex(item).decode()]

            except:
                return [False, item]

    else:
        return [False, item]

if __name__ == "__main__":
    string_type = ""
    run = True
    i = 1
    Parser = argparse.ArgumentParser(description='Tool that automatically decodes a string as many times as needed.')
    Parser.add_argument('-s', '--encodedstring', type=str, help='This option is used to specify an encoded string. To run: ./Google_Drive_Governance -pd domains.txt')
    Parser.add_argument('-f', '--encodedfile', type=str, help='This option is used to specify a file with encoded data inside. To run: ./Google_Drive_Governance -pe emails.txt')
    Arguments = Parser.parse_args()
    item = ""

    if Arguments.encodedstring and Arguments.encodedfile:
        sys.exit("[-] Please only provide one option at a time.")

    elif not Arguments.encodedstring and not Arguments.encodedfile:
        sys.exit("[-] No option provided.")

    elif Arguments.encodedstring and not Arguments.encodedfile:
        item = Arguments.encodedstring

    elif not Arguments.encodedstring and Arguments.encodedfile:
        item = Read_File(Arguments.encodedfile)

    try:

        while run:
            item_list = IdentifyandDecodeString(item, i)
            run = item_list[0]

            if run:
                print(f"[i] Decoded result {str(i)}: \"{item}\".")

            item = item_list[1]
            i += 1

        else:
            print(f"[+] Final decoded string: \"{item}\".")

    except:
        print(f"[!] Error, last decoded result \"{item}\".")
