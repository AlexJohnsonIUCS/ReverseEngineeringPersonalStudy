#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <errhandlingapi.h>

LONG WINAPI VectoredHandlerSkip( struct _EXCEPTION_POINTERS *ExceptionInfo){
    PCONTEXT Context;
    Context = ExceptionInfo -> ContextRecord;
    if(ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ){
        Context-> Rip += 2;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(){
    int var = NULL;
    int *p = NULL;
    int c;
    int a = 5;
    PVOID h1;
    h1 = AddVectoredExceptionHandler(1,VectoredHandlerSkip );
    printf("Before supposed reference issue");
    c= a +*p;


    printf("After reference issue");

    c= a + 9;

    
    return c;
}