#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winbase.h>

int main(){
    HANDLE h = OpenFileMappingA(FILE_MAP_ALL_ACCESS,FALSE,"ChatSynced");
    LPVOID addr = MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0,0,0);

    for(;;){
        printf("%s",(char*) addr);
        printf("\n");
        
        Sleep(1000);

    }

}