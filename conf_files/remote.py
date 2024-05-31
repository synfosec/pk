from conf_files import setting

"""
This is the remote exploit module. Modify the RemoteExploit class to implement the exploit.
"""

class RemoteExploit:
    def __init__(self, target: str, port: int):
        self.target = target
        self.port   = port

        self.exploit()

    def exploit(self):
        # write exploit here

        # task = ""
    
        p = setting.pwn.remote(self.target, self.port)
        p.interactive()

        # p = pwn.listen(args.port)
        # p.wait_for_connection()
