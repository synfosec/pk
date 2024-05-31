import sys
import subprocess
import time
import struct
import argparse
import socket
import os
import pwn
from paramiko.ssh_exception import AuthenticationException
from platform import system as sys_checker
from requests import request
from colorama import Fore, Style
from datetime import datetime
from conf_files import network
from conf_files import payload
from conf_files import remote
from conf_files import binary
from conf_files import pack

#// PARSER OBJECT
parser = argparse.ArgumentParser()

server_group = parser.add_argument_group("Remote Exploitation")
parser.add_argument(
    "-s",
    "--server",
    help="For connecting to a server",
    action="store_true"
)

parser.add_argument(
    "--version",
    help="Prints the version and quits",
    action="store_true"
)

local_group = parser.add_argument_group("Local Exploitation")

local_group.add_argument(
    "--info",
    type=str,
    help="Shows information about the binary"
)

local_group.add_argument(
    "-b",
    "--binary",
    type=str,
    help="Binary file to run"
)

local_group.add_argument(
    "--cyclic",
    type=int,
    help="Generates a cyclic pattern"
)

local_group.add_argument(
    "--find_offset",
    type=str,
    help="Finds the offset of a cyclic pattern"
)

# SHELLCODE COMMANDS
shell_parse = parser.add_argument_group("Shellcode Generation")

shell_parse.add_argument(
    "--payload_create",
    type=str,
    help="Write shellcode to file"
)

shell_parse.add_argument(
    "--shellcode_generate",
    help="Generates shellcode from assembly instructions",
    action="store_true"
)

shell_parse.add_argument(
    "--shellcode_generate_sh",
    help="Generates shellcode for a linux shell",
    action="store_true"
)

shell_parse.add_argument(
    "--shellcode_generate_cat",
    type=str,
    help="Generates shellcode to cat a file"
)

shell_parse.add_argument(
    "--disasm",
    type=str,
    help="Shows the disassembly of shellcode from a file"
)

server_group.add_argument(
    "-a",
    "--address",
    type=str,
    help="Host address to connect to"
)

server_group.add_argument(
    "-p",
    "--port",
    type=int,
    help="Port of the address to connect to"
)

server_group.add_argument(
    "--getserverip",
    help="Gets the IP of the website",
    action="store_true"
)

server_group.add_argument(
    "--ssh",
    help="Connect to SSH server using config [BEING WORKED ON]",
    action="store_true"
)

server_group.add_argument(
    "--net-scan",
    help="Scan the network for devices",
    action="store_true"
)

server_group.add_argument(
    "--network-scan",
    help="Scan a device for open ports",
    action="store_true"
)

server_group.add_argument(
    "--db",
    help="Starts exploit search",
    type=str
)

server_group.add_argument(
    "--ranges",
    type=str,
    help="Port ranges to scan"
)

web_group = parser.add_argument_group("Web Exploitation")

web_group.add_argument(
    "-u",
    "--url",
    type=str,
    help="URL of the address to request to"
)

web_group.add_argument(
    "-r",
    "--request",
    help="For sending an HTTP GET request",
    action="store_true"
)

web_group.add_argument(
    "--post",
    help="For sending an HTTP POST request",
    action="store_true"
)

curr_time         = datetime.now()
user              = os.getlogin()
working_directory = os.getcwd()

#// PROGRAM BANNER
class Banner:
    def __init__(self):
        title = "pk0x1"
        # title = figlet_format("pk",font="epic",width=300)
        banner = Style.BRIGHT + Fore.RED + title + "\t\t\t\t\tby synfosec\n" + Style.RESET_ALL
        print(banner)

#// EXPLOITATION SUCCESS MESSAGE
class SuccessScreen:
    def __init__(self,flag: str):
        print("[!]" + Style.BRIGHT + Fore.GREEN + " Successful compromise!" + Style.RESET_ALL)
        print("[+]" + Style.BRIGHT + Fore.GREEN + " CTF Flag: " + Style.RESET_ALL + Style.BRIGHT + Fore.BLUE + flag + Style.RESET_ALL)

#// CONNECTION CLASS
class Connect:
    def __init__(self):
        CScreen()
        self.connection()

    def connection(self):
        Banner()

        if(args.request and not args.url):
            print("\n[-] " + Style.BRIGHT + Fore.RED + "There has been an error: No URL was provided\n" + Style.RESET_ALL)
            sys.exit(1)

        #//REQUEST
        if(args.request):
            print(f"[*] {curr_time} Initializing all dependencies")
            print("[*] Initializing payloads...")
            print("\n[*] Sending HTTP GET request to " + Style.BRIGHT + Fore.GREEN + "%s" % args.url + Style.RESET_ALL + "...\n\n")

            hea = {}

            res = request('GET',args.url, headers=hea)
            print(Style.BRIGHT + Fore.YELLOW + "GET %s" % res.url + Style.RESET_ALL)
            print(Style.BRIGHT + Fore.YELLOW + "STATUS: %d %s" % (res.status_code, res.reason) + Style.RESET_ALL)
            print(Style.BRIGHT + Fore.GREEN + "HEADERS:\n" + Style.RESET_ALL)

            for key, val in res.headers.items():
                print(Style.BRIGHT + Fore.GREEN + "[+] %s: %s" % (key.upper(), val) + Style.RESET_ALL)

            print(Style.BRIGHT + Fore.YELLOW + "\nHTML\n" + Style.RESET_ALL)
            sys.stdout.buffer.write(res.text.encode())
            sys.exit(0)

        #//POST REQUEST
        if(args.post and not args.url):
            print("\n[-] " + Style.BRIGHT + Fore.RED + "There has been an error: No URL was provided\n" + Style.RESET_ALL)
            sys.exit(1)

        if(args.post):
            print("[*] %s Initializing all dependencies" % curr_time)
            print("[*] Initializing payloads...")
            print("\n[*] Sending HTTP POST request to " + Style.BRIGHT + Fore.GREEN + "%s" % args.url + Style.RESET_ALL + "...\n\n")

            # POST DATA [TODO]
            dat = {}

            res = request('POST',args.url,data=dat)
            print(Style.BRIGHT + Fore.YELLOW + "POST %s" % res.url + Style.RESET_ALL)
            print(Style.BRIGHT + Fore.YELLOW + "STATUS: %d %s" % (res.status_code, res.reason) + Style.RESET_ALL)
            print(Style.BRIGHT + Fore.GREEN + "HEADERS:\n" + Style.RESET_ALL)
            
            for key, val in res.headers.items():
                print(Style.BRIGHT + Fore.GREEN + "[+] %s: %s" % (key.upper(), val) + Style.RESET_ALL)

            print(Style.BRIGHT + Fore.YELLOW + "\nHTML\n" + Style.RESET_ALL)
            sys.stdout.buffer.write(res.text.encode())
            sys.exit(0)

        #// SERVER
        if(args.server):
            print("[+] Logged in as %s" % user)
            print("[+] Running at %s" % working_directory)
            print("[*] %s Initializing all dependencies" % curr_time)
            print("[*] Initializing payloads...")

            if(not args.address or not args.port):
                print("\n[-] " + Style.BRIGHT + Fore.RED + "There has been an error: Provide both the address and port\n" + Style.RESET_ALL)
                sys.exit(1)

            try:
                sInf("Running exploit")
                
                try:
                    remote.RemoteExploit(args.address, args.port)
                except KeyboardInterrupt:
                    print("\n[-] " + Style.BRIGHT + Fore.RED + "KEYBOARJLKSSKLDNFKSJDF PANIC :)" + Style.RESET_ALL + "\nexiting...\n")
            except Exception as error:
                print("\n[+] " + Style.BRIGHT + Fore.RED + "There has been an error: %s\n" % error + Style.RESET_ALL)
                sys.exit(1)

        #// DISCOVER SCAN

        if(args.net_scan):
            print("[*] %s Initializing all dependencies" % curr_time)
            print("[*] Initializing payloads...")

            try:
                NmapCheck()
                print("[+] Running module\n")

                if(not args.address):
                    print("\n[-] " + Style.BRIGHT + Fore.RED + "There has been an error: CIDR needed with the -a flag\n" + Style.RESET_ALL)
                    sys.exit(1)

                network.NetDiscover(args.address)
            except KeyboardInterrupt:
                print("\n[-] " + Style.BRIGHT + Fore.RED + "KEYBOARJLKSSKLDNFKSJDF PANIC :)" + Style.RESET_ALL + "\nexiting...\n")
                sys.exit(0)
            except Exception as e:
                print("\n[-] " + Style.BRIGHT + Fore.RED + "There has been an error: %s\n" % e + Style.RESET_ALL)
                sys.exit(1)

        #// NETWORK SCAN

        if(args.network_scan):
            print("[*] %s Initializing all dependencies" % curr_time)
            print("[*] Initializing payloads...")

            try:
                NmapCheck()
                print("\n[+] Running module")

                if(not args.address or not args.ranges):
                    print("\n[-] " + Style.BRIGHT + Fore.RED + "There has been an error: Provide both the address and port\n" + Style.RESET_ALL)
                    sys.exit(1)

                network.NetworkScan(args.address,args.ranges)
            except KeyboardInterrupt:
                print("\n[-] " + Style.BRIGHT + Fore.RED + "KEYBOARJLKSSKLDNFKSJDF PANIC :)" + Style.RESET_ALL + "\nexiting...\n")
                sys.exit(0)
            except Exception as e:
                print("\n[-] " + Style.BRIGHT + Fore.RED + "There has been an error: %s\n" % e + Style.RESET_ALL)
                sys.exit(1)

        #// BINARY AND DEFAULT
        elif(not args.server):
            print("[*] %s Initializing all dependencies" % curr_time)
            print("[*] Initializing payloads...")

            if(not args.binary and len(sys.argv) < 2):
                print("\n[-] " + Style.BRIGHT + Fore.RED + "There has been an error: No arguments. \"Type -h for help menu\"\n" + Style.RESET_ALL)
                sys.exit(2)

            #// CYCLIC
            if(args.cyclic):
                print("\n[+] " + Style.BRIGHT + Fore.GREEN + "Cyclic Pattern: " + Style.RESET_ALL + pwn.cyclic(args.cyclic).decode() + "\n")
                sys.exit(0)

            #// CYCLIC FIND
            if(args.find_offset):
                find = pwn.cyclic_find(args.find_offset.encode("utf-8"))
                print("\n[+] " + Style.BRIGHT + Fore.GREEN + "Offset: " + Style.RESET_ALL + "\n")
                print("%d bytes" % find)
                print("\n")
                sys.exit(0)

            #// SSH
            if(args.ssh):
                print("[+] Logged in as %s" % user)
                print("[+] Running at %s" % working_directory)
                print("[+] SSH CONNECTION(OK/NONE): OK")
                print("[+] CONNECTION STRIPPING IN 10s: OK")

                try:
                    # [TODO]
                    print("\n[-] Configure SSH function in './conf_files/Setting.py'")
                    sys.exit(0)
                except KeyboardInterrupt:
                    print("\n[-] " + Style.BRIGHT + Fore.RED + "KEYBOARJLKSSKLDNFKSJDF PANIC :)" + Style.RESET_ALL + "\nexiting...\n")
                    sys.exit(0)
                except AuthenticationException:
                    print("\n[-] There has been an error: Invalid Authetnication, username or password may be wrong\n")
                    sys.exit(1)
                except TimeoutError:
                    print("\n[-] Seems we can't establish a connection. Maybe the host is down?")
                    sys.exit(1)
                except Exception as e:
                    print("\n[-] " + Style.BRIGHT + Fore.RED + "There has been an error: %s\n" % e + Style.RESET_ALL)
                    sys.exit(1)

            #//GETSERVERIP
            if(args.getserverip):
                try:
                    s = socket.gethostbyname(args.url)
                    print("\nWebsite IP: %s\n" % s)
                    sys.exit(0)
                except TypeError:
                    print("\n[-] " + Style.BRIGHT + Fore.RED + "There has been an error: Need to use --url\n" + Style.RESET_ALL)
                    sys.exit(1)
                except socket.gaierror:
                    print("\n[-] " + Style.BRIGHT + Fore.RED + "There has been an error: Do not use schemas | https://google.com ==> google.com\n" + Style.RESET_ALL)
                    sys.exit(1)

            #//VERSION
            if(args.version):
                print("\npk: 0.1\n")
                sys.exit(0)

            #//URL ERROR
            if(args.url):
                print("\n[-] " + Style.BRIGHT + Fore.RED + "There has been an error: What are you trying to do with that URL? Lmao...\n" + Style.RESET_ALL)
                sys.exit(1)

            #// SHELLCODE GEN SH

            if(args.shellcode_generate_sh):
                try:
                    print("[+] Logged in as %s" % user)
                    print("[+] Running at %s" % working_directory)
                    
                    print("\n")
                    Inf("Reading assembly")
                    Task("Generating shellcode for /bin/sh...")

                    shell = pack.ShellGenerate()
                    shell.shellcode_create_sh()
                except Exception as e:
                    print("\n[+] " + Style.BRIGHT + Fore.RED + "There has been an error: %s\n" % e + Style.RESET_ALL)

            #// SHELLCODE GEN CAT

            if(args.shellcode_generate_cat):
                try:
                    print("[+] Logged in as %s" % user)
                    print("[+] Running at %s" % working_directory)
                    
                    print("\n")
                    Inf("Reading assembly")
                    Task("Generating shellcode to cat for %s..." % args.shellcode_generate_cat)

                    shell = pack.ShellGenerate()
                    shell.shellcode_create_cat(args.shellcode_generate_cat)
                except Exception as e:
                    print("\n[+] " + Style.BRIGHT + Fore.RED + "There has been an error: %s\n" % e + Style.RESET_ALL)

            #//SHELLCODE GENERATE

            if(args.shellcode_generate):
                try:
                    print("[+] Logged in as %s" % user)
                    print("[+] Running at %s" % working_directory)

                    print("\n")
                    Inf("Reading assembly")
                    Inf("Attempting to generate shellcode")

                    shell = pack.ShellGenerate()
                    shell.asm_create()
                except FileNotFoundError:
                    print("\n[-]" + Fore.RED + " \"shellcode.asm\" not found\n" + Fore.RESET)
                    sys.exit(1)

            #// EXPLOIT SEARCH

            if args.db:
                try:
                    print("[+] Logged in as %s" % user)
                    print("[+] Running at %s" % working_directory)

                    print("\n")
                    Inf("Fetching exploits")

                    subprocess.run(["python", "./conf_files/sploiter/sploiter.py",
                                    f"--keyword={args.db}",
                                    "--exploitdb",
                                    "--packetstorm",
                                    "--nvd",
                                    "--msfmodule",
                                    "-ot html",
                                    f"-output {args.db}"
                    ])

                    print("\n")
                    Task("Done!")
                    print("\n")
                    sys.exit(0)

                except FileNotFoundError:
                    print("\n[-]" + Fore.RED + " \"shellcode.asm\" not found\n" + Fore.RESET)
                    sys.exit(1)

            #//INFO

            if args.info:
                try:
                    print("[+] Logged in as %s" % user)
                    print("[+] Running at %s" % working_directory)

                    print("\n")
                    Inf("Reading binary")
                    Inf("Calculating size")
                    Inf("Checking security of %s" % args.info)

                    binary.Info(args.info)

                    Task("Done!")
                    print("\n")

                    sys.exit(0)
                except Exception as e:
                    print("\n[+] " + Style.BRIGHT + Fore.RED + "There has been an error: %s\n" % e + Style.RESET_ALL)
                    sys.exit(1)

            #//DISASM
            if args.disasm:
                try:
                    print("[+] Logged in as %s" % user)
                    print("[+] Running at %s" % working_directory)

                    print("\n")
                    Inf("Reading shellcode")
                    Task("Disassembling shellcode from %s..." % args.disasm)

                    payload.Assemble(args.disasm)
                except Exception as e:
                    print("\n[+] " + Style.BRIGHT + Fore.RED + "There has been an error: %s\n" % e + Style.RESET_ALL)
                    sys.exit(1)

            #//PAYLOAD CREATE

            if(args.payload_create):
                try:
                    print("[+] Logged in as %s" % user)
                    print("[+] Running at %s" % working_directory)
                    
                    payload.Payload(args.payload_create)
                except Exception as e:
                    print("\n[+] " + Style.BRIGHT + Fore.RED + "There has been an error: %s\n" % e + Style.RESET_ALL)
                    sys.exit(1)

            if(not args.binary):
                print("\n[-] " + Style.BRIGHT + Fore.RED + "There has been an error: Binary filename needs to be provided\n" + Style.RESET_ALL)
                sys.exit(1)

            #//BINARY
            try:
                print("[+] Logged in as %s" % user)
                print("[+] Running at %s" % working_directory)

                b = binary.Binary(args.binary)
                b.exploit()
                
            except Exception as e:
                print("\n[+] " + Style.BRIGHT + Fore.RED + "There has been an error: %s\n" % e + Style.RESET_ALL)
                sys.exit(1)

class NmapCheck(object):
    def __init__(self) -> None:
        self.check_map()

    def check_map(self):
        if(sys_checker()=="Windows"):
            try:
                os.system("nmap --version")
            except FileNotFoundError:
                print("\n[-] " + Style.BRIGHT + Fore.RED + "There has been an error: Nmap is not installed on this system\n" + Style.RESET_ALL)
                sys.exit(1)
        elif(sys_checker()=="Linux"):
            try:
                os.system("nmap --version")
            except FileNotFoundError:
                print("\n[-] " + Style.BRIGHT + Fore.RED + "There has been an error: Nmap is not installed on this system\n" + Style.RESET_ALL)
                sys.exit(1)
        elif(sys_checker()=="Darwin"):
            try:
                os.system("nmap --version")
            except FileNotFoundError:
                print("\n[-] " + Style.BRIGHT + Fore.RED + "There has been an error: Nmap is not installed on this system\n" + Style.RESET_ALL)
                sys.exit(1)
        else:
            print("\n[-] " + Style.BRIGHT + Fore.RED + "UNKNOWN PLATFORM\n" + Style.RESET_ALL)
            sys.exit(1)

#// TO CLEAR THE TERMINAL
class CScreen:
    def __init__(self) -> None:
        if(sys_checker()=="Windows"):
            os.system("cls")
        elif(sys_checker()=="Linux"):
            os.system("clear")
        elif(sys_checker()=="Darwin"):
            os.system("clear")
        else:
            print("\n[-] UNKNOWN PLATFORM")
            sys.exit(1)

class Inf:
    def __init__(self, msg: str):
        pwn.log.info(msg)

class Task:
    def __init__(self, msg: str):
        pwn.log.success(msg)

class sInf:
    def __init__(self, msg: str):
        pwn.log.success(msg)

args = parser.parse_args()
