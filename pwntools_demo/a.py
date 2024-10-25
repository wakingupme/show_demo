from pwn import*

p = process('./main')

p.sendlineafter("If you are ready, press the Enter key to start our challenge.",b'')

a = int(p.recvuntil(b'*')[:-2])
b = int(p.recvuntil(b'=')[:-2])
c = int(a * b)

p.sendline(str(c).encode())

p.interactive()
