#include <stdio.h>
#include <stdlib.h>

char *shell = "/bin/sh";

void g8g0ts(){
       asm(
        ".intel_syntax noprefix;"
        "syscall;"
        "ret;"
        ".att_syntax;"
    );

}

void set_rax(){
          asm(
        ".intel_syntax noprefix;"
        "pop rax;"
        "ret;"
        "pop rdi;"
        "ret;"
        ".att_syntax;"
    );

}

int main(void)
{
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin, 0LL, 1, 0LL);
    
    char buf[100];

    printf("This time, no system() and NO SHELLCODE!!!\n");
    printf("What do you plan to do?\n");
    gets(buf);
    asm(
        ".intel_syntax noprefix;"
        "xor rdx,rdx;"
        "xor rsi,rsi;"
        ".att_syntax;"
    );
    return 0;
}
