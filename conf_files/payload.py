import sys
from conf_files import setting

class Payload:
    def __init__(self, ars):
        self.args = ars

        # write payload here

        payload = ""

        if payload == "":
            print("\n[-] " + setting.Style.BRIGHT + setting.Fore.RED + "There has been an error: Payload is empty!\n" + setting.Style.RESET_ALL)
            sys.exit(1)
        else:
            file = open(self.args, "wb")
            setting.Inf("Writing %d bytes to \"%s\"" % (len(payload), self.args))
            file.write(payload)
            setting.Task("Done!")
            file.close
            print("\n")
            setting.Inf("Closed %s!" % self.args)
            print("\n")

        sys.exit(0)

class Assemble:
    def __init__(self, file: str):
        self.file = file

        shellcode = open(self.file, "rb").read()

        print("\n=====================================")
        print("              SHELLCODE")
        print("=====================================\n")
        print(shellcode)
        print("\n")
        print("=====================================")
        print("              DISASSEMBLY")
        print("=====================================\n")
        print(setting.pwn.disasm(shellcode))
        print("\n")
        setting.sys.exit(0)
