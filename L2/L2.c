#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

int main(){
    //14580 is PID notepad
    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 14580);
    if(h==NULL){
        printf("Failed to open process");
        exit(EXIT_FAILURE);
    }
    printf("Notebook Handle PID: %p\n",h);
    printf("Check System Informer now. Press Enter to close...\n");
    getchar();
    CloseHandle(h);
    return 0;
}