import nmap
import sys
import os
from datetime import datetime
from colorama import Fore
from colorama import Style

class NetDiscover:
    def __init__(self, cidr: str) -> None:
        print("[+] Searching for scanable targets...\n")
        self.cidr = cidr

        try:
            scanner = nmap.PortScanner()
            scan = scanner.scan(hosts=self.cidr, arguments="-sn")
            
            print("[+] Scan results: \n")

            if(os.path.isfile("./hosts_list.txt")):
                os.remove("./hosts_list.txt")

            scan_file = open("hosts_list.txt", "w")
            scan_file.write("HOSTS %s:\n\n" % datetime.now())

            for i in scan['scan']:
                print(Style.BRIGHT + Fore.GREEN + "==> " + Style.RESET_ALL + "%s is up!" % i)
                scan_file.write(i + '\n')

            scan_file.close()
            print("\n[+] Hosts saved to file\n")
            sys.exit(0)
        except KeyboardInterrupt:
            print("\n[-] Stopping scan and closing...")
            sys.exit(1)
        except Exception as e:
            print("\n[-] There has been an error: %s\n" % e)
            sys.exit(1)

class NetworkScan:
    def __init__(self, ip_address: str, port: str) -> None:
        print(f"[+] Scanning {ip_address} on port {port}...\n")
        self.ip_address = ip_address
        self.port = port

        try:
            scanner = nmap.PortScanner()
            scan = scanner.scan(hosts=self.ip_address, arguments=f"-sS -p {self.port} -v")

            print("[+] Scan results: \n")

            for host in scan['scan']:
                print(Style.BRIGHT + Fore.GREEN + "==> " + Style.RESET_ALL + "Host: %s\n" % self.ip_address)
                print(Style.BRIGHT + Fore.GREEN + "==> " + Style.RESET_ALL + "State: %s" % scan['scan'][host]['status']['state'])

                for proto in scan['scan'][host]['tcp']:
                    state = scan['scan'][host]['tcp'][proto]['state']
                    print(Style.BRIGHT + Fore.GREEN + "==> " + Style.RESET_ALL + "Port: %s\tState: %s" % (proto, state))

            print("\n[+] Scan completed\n")
            sys.exit(0)
        except KeyboardInterrupt:
            print("\n[-] Stopping scan and closing...")
            sys.exit(1)
        except Exception as e:
            print("\n[-] There has been an error: %s\n" % e)
            sys.exit(1)
