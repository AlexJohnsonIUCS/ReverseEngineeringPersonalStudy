#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(){
    char *msg = "You sly Debugger";
    for (int i = 0; msg[i] != '\0'; i++) {
        printf("0x%02X, ", msg[i] ^ 0x55);
    }
}