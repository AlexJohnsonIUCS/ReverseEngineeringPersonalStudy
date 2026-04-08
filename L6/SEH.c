#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <errhandlingapi.h>

int main(){
    int var = NULL;
    int *p = NULL;
    int c;
    int a = 5;

    __try{
        printf("Attempting to derefrence null pointer\n");
        c = a + *p;

    }
    __except(GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION){
        printf("Exeception caught\n");
        c= a +9;

    }
    return c;
}