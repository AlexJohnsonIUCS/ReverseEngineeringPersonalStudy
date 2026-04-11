#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Tlhelp32.h>
#include <string.h>
#include <synchapi.h>
#include <stdint.h>



int main(){
    LARGE_INTEGER DebugCheck;
    QueryPerformanceCounter(&DebugCheck);
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);
    if(ctx.Dr0!=0 || ctx.Dr1!=0||ctx.Dr2!=0||ctx.Dr3!=0){
        printf("Stop trying to debug me.");
        exit(EXIT_FAILURE);
    }
    HANDLE AllProcSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL,0);
    PROCESSENTRY32 currProcess;
    currProcess.dwSize=  sizeof(PROCESSENTRY32);
    char processToSearch[512];
    BOOL found = FALSE;
    if(IsDebuggerPresent()==TRUE){
        printf("You sly Debugger");
        exit(EXIT_FAILURE);
    }
    LARGE_INTEGER end;
    QueryPerformanceCounter(&end);
    if (end.QuadPart - DebugCheck.QuadPart > 100000) {
        printf("Timing anomaly detected — debugger likely stepping through code\n");
        exit(EXIT_FAILURE);
    }
    printf("What process would you like to inspect? Make sure naming convention is __NAME__.exe\n");
    scanf_s("%511s",processToSearch,512);
    if(processToSearch[0] == '\0'){
        printf("You did not enter a process, exiting");
        exit(EXIT_FAILURE);
    }
    if(Process32First(AllProcSnapshot,&currProcess)==FALSE){
        printf("Failure to grab first process. Error Code-> %lu\n", GetLastError());
        exit(EXIT_FAILURE);
    }
    if(strcmp(processToSearch,currProcess.szExeFile)==0){found = TRUE;}
    while(!found && Process32Next(AllProcSnapshot,&currProcess)){
        printf("Wrong Process, Continuing but make sure the process is running\n");
        if(strcmp(processToSearch,currProcess.szExeFile)==0){found = TRUE;}
    }
    CloseHandle(AllProcSnapshot);
    if(!found){ 
        printf("Process was never found, Exiting\n"); 
        return 1; 
    }
    HANDLE Process = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,currProcess.th32ProcessID);
    if(!Process){ 
        printf("Module Snapshot failed\n"); 
        return 1; 
    }
    MODULEENTRY32 currModule;
    MODULEENTRY32 firstModule;
    currModule.dwSize = sizeof(MODULEENTRY32);
    firstModule.dwSize=sizeof(MODULEENTRY32);
    if(Module32First(Process,&firstModule)==FALSE){
        printf("Error in grabbing ModuleFirst, Error Code-> %lu\n", GetLastError());
        printf("\nExiting...\n");
        exit(EXIT_FAILURE);
    }
    if(Module32First(Process,&currModule)==FALSE){
        printf("Error in grabbing ModuleFirst, Error Code-> %lu\n", GetLastError());
        printf("\nExiting...\n");
        exit(EXIT_FAILURE);
    }else{
        printf("Module Name: %s \n",currModule.szExePath);
        printf("Module Base Address: %p \n", currModule.modBaseAddr);
        printf("Module Size: %x \n",currModule.modBaseSize);
    }
    while(Module32Next(Process,&currModule)){
        printf("Module Name: %s \n",currModule.szExePath);
        printf("Module Base Address: %p \n", currModule.modBaseAddr);
        printf("Module Size: %x \n",currModule.modBaseSize);
    }
    CloseHandle(Process);
    HANDLE ThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, currProcess.th32ProcessID);
    if(!ThreadSnap){
        printf("Threadsnapshot failed exiting...\n");
        exit(EXIT_FAILURE);
    }
    THREADENTRY32 currThread;
    currThread.dwSize=sizeof(THREADENTRY32);
    if(Thread32First(ThreadSnap,&currThread)==FALSE){
        printf("Failure in grabbing first Thread, Error Code-> %lu\n", GetLastError());
        exit(EXIT_FAILURE);
    }
    if(currThread.th32OwnerProcessID==currProcess.th32ProcessID){
        printf("Thread ID: %x\n",currThread.th32ThreadID);
    }
    while(Thread32Next(ThreadSnap,&currThread)){
        if(currThread.th32OwnerProcessID==currProcess.th32ProcessID){
            printf("Thread ID: %x\n",currThread.th32ThreadID);
        }
    }
    CloseHandle(ThreadSnap);
    HANDLE iat = OpenProcess(PROCESS_ALL_ACCESS,FALSE,currProcess.th32ProcessID);
    IMAGE_DOS_HEADER dosHead;
    SIZE_T bytesRead;
    if(!ReadProcessMemory(iat,firstModule.modBaseAddr,&dosHead,sizeof(IMAGE_DOS_HEADER),&bytesRead)){
        printf("Failed to read DOS header\n");
        return 1;
    }
    IMAGE_NT_HEADERS nt;
    if(!ReadProcessMemory(iat,firstModule.modBaseAddr+dosHead.e_lfanew,&nt,sizeof(IMAGE_NT_HEADERS),&bytesRead)){
        printf("Failed to read NT headers\n");
        return 1;
    }
    DWORD importRVA = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    DWORD importOffset = 0;
    IMAGE_IMPORT_DESCRIPTOR imports;
    printf("\n--- IAT DUMP ---\n");
    while(1){
        ReadProcessMemory(iat,firstModule.modBaseAddr+importRVA+importOffset,&imports,sizeof(IMAGE_IMPORT_DESCRIPTOR),&bytesRead);
        if(imports.Name==0) break;
        char name[256];
        ReadProcessMemory(iat,firstModule.modBaseAddr+imports.Name,name,sizeof(name),&bytesRead);
        printf("\nDLL: %s\n",name);
        DWORD thunkOffset=0;
        IMAGE_THUNK_DATA thunk;
        while(1){
            ReadProcessMemory(iat,firstModule.modBaseAddr+imports.OriginalFirstThunk+thunkOffset,&thunk,sizeof(IMAGE_THUNK_DATA),&bytesRead);
            if(thunk.u1.AddressOfData==0) break;
            if(!(thunk.u1.Ordinal & IMAGE_ORDINAL_FLAG)){
                char importBuf[256];
                ReadProcessMemory(iat, firstModule.modBaseAddr + thunk.u1.AddressOfData, importBuf, sizeof(importBuf), &bytesRead);
                printf("  Function: %s\n", importBuf + 2);
            }
            thunkOffset+=sizeof(IMAGE_THUNK_DATA);
        }
        importOffset+=sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
    CloseHandle(iat);
    printf("\nPress Enter to exit...\n");
    getchar();
    getchar();
    return 0;

}