#include<stdio.h>
#include<unistd.h>
#include<sys/mman.h>

char shellcode[0x200];

void gadget(){
	asm(
	".intel_syntax noprefix;"
	"pop rdi;"
	"ret;"
	".att_syntax;");
}

void backdoor(char *addr){
	mprotect(addr,0x1000,7);
}

int main(){
	char buf[0x20];
	read(0,shellcode,0x200);
	read(0,buf,0x50);
}
