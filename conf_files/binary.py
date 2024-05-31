import tabulate
from conf_files import setting

"""
This is the binary exploit module. Modify the Binary class to implement the exploit.
"""

class Binary:
    def __init__(self, binary: str):
        self.binary = binary
        self.exploit()

    def exploit(self):

        # write exploit here

        p = setting.pwn.process(self.binary)
        p.interactive()
        setting.sys.exit(0)

class Info:
    def __init__(self, binary: str):
        self.binary = binary
        b = setting.pwn.ELF(self.binary)

        print("\n=====================================")
        print("              ARCHITECTURE")
        print("=====================================\n")

        print(tabulate.tabulate([["Arch", b.arch], ["Bits", b.bits], ["Endian", b.endian], ["OS", b.os], ["Relro", b.relro], ["NX", b.nx], ["PIE", b.pie], ["Canary", b.canary], ["Fortify", b.fortify], ["Data", len(b.data)], ["Got", b.got], ["Plt", b.plt], ["Bss", b.bss]], headers=["Property", "Value"], tablefmt="fancy_grid"))

        print("\n=====================================")
        print("              SYMBOLS")
        print("=====================================\n")

        symbols = b.symbols
        sym_amount = []

        for symbol in symbols:
            print(symbol)
            sym_amount.append(symbol)

        print("\n")
        setting.Task("Total symbols: " + str(len(sym_amount)))
