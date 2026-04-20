#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Tlhelp32.h>
#include <string.h>
#include <synchapi.h>
#include <stdint.h>


void decrypt(char *buf, int len, char key) {
    for (int i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

void debuggerCheck(){
    if(IsDebuggerPresent()==TRUE){
        char encMsg[] = {0x0C, 0x3A, 0x20, 0x75, 0x26, 0x39, 0x2C, 0x75, 0x11, 0x30, 0x37, 0x20, 0x32, 0x32, 0x30, 0x27};
        decrypt(encMsg, sizeof(encMsg)-1, 0x55);
        printf("%s",encMsg);
        memset(encMsg, 0, sizeof(encMsg));
        exit(EXIT_FAILURE);
    }
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);
    if(ctx.Dr0!=0 || ctx.Dr1!=0||ctx.Dr2!=0||ctx.Dr3!=0){
        char encMsg[] = {0x06, 0x21, 0x3A, 0x25, 0x75, 0x21, 0x27, 0x2C, 0x3C, 0x3B, 0x32, 0x75, 0x21, 0x3A, 0x75, 0x31, 0x30, 0x37, 0x20, 0x32, 0x75, 0x38, 0x30, 0x7B};
        decrypt(encMsg, sizeof(encMsg)-1, 0x55);
        printf("%s",encMsg);
        memset(encMsg, 0, sizeof(encMsg));
        exit(EXIT_FAILURE);
    }
}
void ModuleDumper(PROCESSENTRY32 c){
    HANDLE Process = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,c.th32ProcessID);
    if(!Process){ 
        printf("Module Snapshot failed\n"); 
        return 1; 
    }
    MODULEENTRY32 currModule;
    currModule.dwSize = sizeof(MODULEENTRY32);
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
    printf("Finished, heading back to main\n");
    return NULL;
}

void ThreadDumper(PROCESSENTRY32 c){
    HANDLE ThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, c.th32ProcessID);
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
    if(currThread.th32OwnerProcessID==c.th32ProcessID){
        printf("Thread ID: %x\n",currThread.th32ThreadID);
    }
    while(Thread32Next(ThreadSnap,&currThread)){
        if(currThread.th32OwnerProcessID==c.th32ProcessID){
            printf("Thread ID: %x\n",currThread.th32ThreadID);
        }
    }
    CloseHandle(ThreadSnap);
    printf("Finished, heading back to main\n");
    return NULL;
}

void IATDumper(PROCESSENTRY32 c){
    HANDLE Process = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,c.th32ProcessID);
    if(!Process){ 
        printf("Module Snapshot failed\n"); 
        return 1; 
    }
    MODULEENTRY32 firstModule;
    firstModule.dwSize=sizeof(MODULEENTRY32);
    if(Module32First(Process,&firstModule)==FALSE){
        printf("Error in grabbing ModuleFirst, Error Code-> %lu\n", GetLastError());
        printf("\nExiting...\n");
        exit(EXIT_FAILURE);
    }
    HANDLE iat = OpenProcess(PROCESS_ALL_ACCESS,FALSE,c.th32ProcessID);
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
    CloseHandle(Process);
    printf("Finished, heading back to main\n");
    return NULL;
}

void MemoryScanner(PROCESSENTRY32 c, int value){
    HANDLE h1 = OpenProcess(PROCESS_ALL_ACCESS, FALSE, c.th32ProcessID);
    MEMORY_BASIC_INFORMATION info;
    unsigned char *addr = NULL;
    SIZE_T bytesRead;
    SIZE_T capacity = 100000;
    unsigned char **candidates = malloc(capacity * sizeof(unsigned char *));
    SIZE_T count = 0;
    while(VirtualQueryEx(h1, addr, &info, sizeof(info))){
        if(info.State == MEM_COMMIT && info.Protect != PAGE_NOACCESS && !(info.Protect & PAGE_GUARD)){
            unsigned char *regionBuf = malloc(info.RegionSize);
            if(regionBuf && ReadProcessMemory(h1, addr, regionBuf, info.RegionSize, &bytesRead)){
                for(SIZE_T i = 0; i <= bytesRead - sizeof(int); i += 4){
                    int val = *(int *)(regionBuf + i);
                    if(val == value){
                        if(count < capacity) candidates[count++] = addr + i;
                    }
                }
            }
            free(regionBuf);
        }
        addr += info.RegionSize;
    }
    printf("Candidates found: %d\n",count);
    int iter =0;
    while(count>1){
        printf("Next Memory Scan Enter new value\n");
        int newVal;
        char ValLookedFor[20];
        scanf_s("%20s",ValLookedFor,20);
        newVal=atoi(ValLookedFor);
        SIZE_T narrowed = 0;
        int val;
        for (SIZE_T i = 0; i < count; i++) {
            if (ReadProcessMemory(h1, candidates[i], &val, sizeof(int), &bytesRead)) {
                if (val == newVal) {
                    candidates[narrowed++] = candidates[i];
                }
            }
        }
        count = narrowed;
        printf("Candidates remaining: %zu\n", count);
    }
    if(count>0){
        printf("Found address: %p\n", candidates[0]);
    }else{
        printf("Value was not found in program...\n");
    }
    free(candidates);
    CloseHandle(h1);
    
    return NULL;
}

void ContinuousScanner(PROCESSENTRY32 c, unsigned char *addr) {
    HANDLE h1 = OpenProcess(PROCESS_ALL_ACCESS, FALSE, c.th32ProcessID);
    int val;
    SIZE_T bytesRead;
    printf("Monitoring address %p. Press Ctrl+C to stop.\n", addr);
    while (1) {
        if (ReadProcessMemory(h1, addr, &val, sizeof(int), &bytesRead)) {
            printf("[%p] Value: %d\n", addr, val);
        } else {
            printf("Read failed — process may have exited.\n");
            break;
        }
        Sleep(1000);
    }
    CloseHandle(h1);
}


int main(){
    debuggerCheck();
    HANDLE AllProcSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL,0);
    int numofProc = 0;
    PROCESSENTRY32 Processes[1024];
    for(int j=0;j<1024;j++){
        Processes[j].dwSize=sizeof(PROCESSENTRY32);
    }
    if(Process32First(AllProcSnapshot,&Processes[0])){
        printf("Process Num: %d : %s\n",0, Processes[0].szExeFile);
        numofProc++;
    }
    int i = 1;
    while(Process32Next(AllProcSnapshot,&Processes[i])){
        printf("Process Num: %d : %s\n",i, Processes[i].szExeFile);
        numofProc++;
        i++;
    }
    while(TRUE){
        char ProcNum[20];
        printf("Choose a Process to inspect. Please write the number of the process.\n");
        scanf_s("%20s",ProcNum,20);
        int selectedIndex=atoi(ProcNum);
        if(selectedIndex<0||selectedIndex>numofProc-1){
            printf("Invalid Process ID, exitting please reopen.");
            exit(EXIT_FAILURE);
        }
        printf("You have selected: %s\n",Processes[selectedIndex].szExeFile);
        printf("Enter 1 if you would like to: Dump Modules (base address, size, path)\n");
        printf("Enter 2 if you would like to: Dump Threads (thread IDs)\n");
        printf("Enter 3 if you would like to: Dump IAT (imported DLLs and functions)\n");
        printf("Enter 4 if you would like to: Scan Memory (search for a value)\n");
        printf("Enter 5 if you would like to: Monitor Address (continuously read an address, get Address from Scan Memory)\n");
        printf("Enter 6 if you would like to: Exit\n");
        char OptionChoice[2];
        scanf_s("%2s",OptionChoice,2);
        int OptionFinal = atoi(OptionChoice);
        if(OptionFinal==6){
            break;
        }else if(OptionFinal==5){
            debuggerCheck();
            char addrInput[20];
            printf("Enter the address to monitor (from Scan Memory, e.g. 00007FF...): \n");
            scanf_s("%20s", addrInput, 20);
            unsigned char *monitorAddr = (unsigned char *)strtoull(addrInput, NULL, 16);
            ContinuousScanner(Processes[selectedIndex], monitorAddr);
            
        }else if(OptionFinal==4){
            debuggerCheck();
            int val;
            char ValLookedFor[20];
            printf("Enter the Value you are looking for within the process.\n");
            scanf_s("%20s",ValLookedFor,20);
            val=atoi(ValLookedFor);
            MemoryScanner(Processes[selectedIndex],val);



        }else if(OptionFinal==3){
            debuggerCheck();
            IATDumper(Processes[selectedIndex]);

        }else if(OptionFinal==2){
            debuggerCheck();
            ThreadDumper(Processes[selectedIndex]);
        }else if(OptionFinal==1){
            debuggerCheck();
            ModuleDumper(Processes[selectedIndex]);
        }
    }
    printf("Thank you for using my tool! Come again.");
    exit(EXIT_SUCCESS);
    return 0;
    
}