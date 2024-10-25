#include <stdio.h>
#include <unistd.h>

void gggddd_1(){
    asm(
    ".intel_syntax noprefix;"
    "pop rdi;"
    "ret;"
    ".att_syntax;"
);
}

int main(){
    char buffer[0x30] = {0};
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("this you only have 0x10 bytes to over!!\n");
    printf("what can you do?\n");
    read(0, buffer, 0x40);
    return 0;
}
