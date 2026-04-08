#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winbase.h>

int main(){
    HANDLE h = CreateFileMappingA(INVALID_HANDLE_VALUE,NULL,PAGE_READWRITE, 0,512,"ChatSynced");
    LPVOID addr = MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0,0,0);

    for(;;){
        scanf_s("%511s",(char*) addr,512 );

    }

}