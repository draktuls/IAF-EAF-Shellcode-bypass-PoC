#pragma once 
#include "defs.h"

extern LPVOID get_base_address();
extern LPVOID help_GetModuleHandle(WCHAR* module_name);
extern void * help_GetProcAddress(LPVOID module, char* func_name, rop_gadget * gadget);
extern void * GetProcAddressIAT(LPVOID module, char* func_name, rop_gadget * gadget);
extern void * GetProcAddressIAT_Normal(LPVOID module, char* func_name, rop_gadget * gadget);
extern void HookIATFunction(LPVOID module, char* func_name, rop_gadget * read_gadget, rop_gadget * write_gadget, char * new_func_pointer, ptrVirtualProtect _VirtualProtect);
extern void * help_GetProcAddress_Fail(LPVOID module, char* func_name, rop_gadget * gadget);
