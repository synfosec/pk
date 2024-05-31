from conf_files import setting

class ShellGenerate:
    def __init__(self):
        pass

    def asm_create(self):
        shellcode = open("shellcode.asm", "r").read()
        print("\n=====================================")
        print("              SHELLCODE")
        print("=====================================\n")
        print(setting.pwn.asm(shellcode))
        print("\n")
        print("=====================================")
        print("              DISASSEMBLY")
        print("=====================================\n")
        print(setting.pwn.disasm(setting.pwn.asm(shellcode)))
        print("\n")
        setting.sys.exit(0)

    def shellcode_create_sh(self):
        shellcode = setting.pwn.shellcraft.i386.linux.sh()

        print("\n=====================================")
        print("              SHELLCODE")
        print("=====================================\n")
        print(setting.pwn.asm(shellcode))
        print("\n")
        print("=====================================")
        print("              DISASSEMBLY")
        print("=====================================\n")
        print(shellcode)
        print("\n")
        setting.sys.exit(0)

    def shellcode_create_cat(self, file: str):
        shellcode = setting.pwn.shellcraft.i386.linux.cat(file)

        print("\n=====================================")
        print("              SHELLCODE")
        print("=====================================\n")
        print(setting.pwn.asm(shellcode))
        print("\n")
        print("=====================================")
        print("              DISASSEMBLY")
        print("=====================================\n")
        print(shellcode)
        print("\n")
        setting.sys.exit(0)
