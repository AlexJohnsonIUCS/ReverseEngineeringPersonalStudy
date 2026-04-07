#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

typedef int (WINAPI *MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
MessageBoxA_t OriginalMessageBoxA = NULL;

int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    return OriginalMessageBoxA(hWnd, "HOOKED!", "HOOKED TITLE", uType);
}

int main() {
    HMODULE proc = GetModuleHandle(NULL);
    if (proc == NULL) {
        printf("Failure in getting module handle");
        return 0;
    }

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)proc;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((unsigned char *)proc + dos->e_lfanew);
    IMAGE_IMPORT_DESCRIPTOR *imports = (IMAGE_IMPORT_DESCRIPTOR *)((unsigned char *)proc + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (imports->Name != 0) {
        char *name = (char *)proc + imports->Name;
        if (_stricmp(name, "USER32.dll") == 0) {
            IMAGE_THUNK_DATA *origThunk = (IMAGE_THUNK_DATA *)((unsigned char *)proc + imports->OriginalFirstThunk);
            IMAGE_THUNK_DATA *iatThunk = (IMAGE_THUNK_DATA *)((unsigned char *)proc + imports->FirstThunk);

            while (origThunk->u1.AddressOfData != 0) {
                if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    IMAGE_IMPORT_BY_NAME *importName = (IMAGE_IMPORT_BY_NAME *)((unsigned char *)proc + origThunk->u1.AddressOfData);
                    if (strcmp(importName->Name, "MessageBoxA") == 0) {
                        DWORD oldProtect;
                        VirtualProtect(&iatThunk->u1.Function, sizeof(void *), PAGE_READWRITE, &oldProtect);
                        OriginalMessageBoxA = (MessageBoxA_t)iatThunk->u1.Function;
                        iatThunk->u1.Function = (ULONG_PTR)HookedMessageBoxA;
                        VirtualProtect(&iatThunk->u1.Function, sizeof(void *), oldProtect, &oldProtect);
                        printf("Hook installed!\n");
                        break;
                    }
                }
                origThunk++;
                iatThunk++;
            }
            break;
        }
        imports++;
    }

    MessageBoxA(NULL, "Hello", "Title", MB_OK);
    return 0;
}