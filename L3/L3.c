#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Tlhelp32.h>

int main(){
    //Creates snapshot of all processes open
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    //Type process, used to step through snapshot
    PROCESSENTRY32 p;
    //Setting the size of P so that it isn't broken by microsoft updated
    p.dwSize = sizeof(PROCESSENTRY32);
    //check and step first process in snapshot
    if(Process32First(h,&p)){
        printf("PID: %lu     Name:%s\n ",p.th32ProcessID,p.szExeFile);
    }
    //step all other processes in snapshot
    while(Process32Next(h,&p)){
        printf("PID: %lu     Name:%s\n ",p.th32ProcessID,p.szExeFile);
    }
    CloseHandle(h);
    return 0;

}