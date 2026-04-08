#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Tlhelp32.h>
#include <string.h>
#include <synchapi.h>

struct threadScan{
    HANDLE handle;
    unsigned char** cand;
    SIZE_T narrow;
    volatile BOOL fl;
    CRITICAL_SECTION cs;
};

DWORD WINAPI ThreadScan(LPVOID lpParam){
    struct threadScan *ts = (struct threadScan*) lpParam;
    while(1){
        EnterCriticalSection(&ts->cs);
        int val;
        SIZE_T bytesRead;
        for(SIZE_T i = 0; i < ts->narrow; i++){
            if(ReadProcessMemory(ts->handle, ts->cand[i], &val, sizeof(int), &bytesRead)){
                printf("[%p] Health: %d\n", ts->cand[i], val);
            }
        }
        LeaveCriticalSection(&ts->cs);
        if(ts->fl == TRUE){
            return 0;
        }
        Sleep(100);
        
    }
}

int main(){
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 p;
    p.dwSize = sizeof(PROCESSENTRY32);
    char fn[] = "Lab1.exe";
    BOOL found = FALSE;
    if(Process32First(h, &p)){
        if(strcmp(fn, p.szExeFile) == 0) found = TRUE;
    }
    while(!found && Process32Next(h, &p)){
        if(strcmp(fn, p.szExeFile) == 0) found = TRUE;
    }
    CloseHandle(h);
    if(!found){ printf("Process not found\n"); return 1; }

    HANDLE h1 = OpenProcess(PROCESS_ALL_ACCESS, FALSE, p.th32ProcessID);
    if(!h1){ printf("OpenProcess failed\n"); return 1; }

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
                    if(val == 100){
                        if(count < capacity) candidates[count++] = addr + i;
                    }
                }
            }
            free(regionBuf);
        }
        addr += info.RegionSize;
    }

    printf("Found %zu candidates with value 100\n", count);
    printf("Waiting 15 seconds for health to tick down...\n");
    Sleep(15000);

    int val;
    SIZE_T narrowed = 0;
    for(SIZE_T i = 0; i < count; i++){
        if(ReadProcessMemory(h1, candidates[i], &val, sizeof(int), &bytesRead)){
            if(val != 100 && val > 0 && val < 100){
                printf("Candidate %p now holds %d\n", candidates[i], val);
                candidates[narrowed++] = candidates[i];
            }
        }
    }

    printf("\nNarrowed to %zu candidates. Monitoring...\n", narrowed);
    CRITICAL_SECTION cs;
    InitializeCriticalSection(&cs);
    struct threadScan ts= {h1,candidates,narrowed,FALSE,cs};
    DWORD TID;
    HANDLE th = CreateThread(NULL, 0, ThreadScan, &ts,0,&TID);
    getchar();
    ts.fl=TRUE;
    WaitForSingleObject(th,INFINITE);
    CloseHandle(th);
    DeleteCriticalSection(&cs);
    free(candidates);
    CloseHandle(h1);
    return 0;
}