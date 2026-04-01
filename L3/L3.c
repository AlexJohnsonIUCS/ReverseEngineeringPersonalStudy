#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Tlhelp32.h>

int main(){
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    PROCESSENTRY32 p;
    p.dwSize = sizeof(PROCESSENTRY32);
    if(Process32First(h,&p)){
        printf("PID: %lu     Name:%s\n ",p.th32ProcessID,p.szExeFile);
    }
    while(Process32Next(h,&p)){
        printf("PID: %lu     Name:%s\n ",p.th32ProcessID,p.szExeFile);
    }
    CloseHandle(h);
    return 0;

}